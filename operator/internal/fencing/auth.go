package fencing

import (
	"context"
	"strings"

	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const TokenAudience = "sekvyr-fence"
const podUIDExtra = "authentication.kubernetes.io/pod-uid"
const podNameExtra = "authentication.kubernetes.io/pod-name"

type Identity struct {
	Namespace         string
	ServiceAccount    string
	ServiceAccountUID string
	PodName           string
	PodUID            string
}

func (Identity) String() string   { return "fencing identity [redacted]" }
func (Identity) GoString() string { return "fencing identity [redacted]" }

type Authenticator interface {
	Authenticate(context.Context, string, journal.Enrollment) (Identity, error)
}

// TokenAuthenticator delegates signature, expiry, audience and bound-token
// validation to the API server. The Reader must be uncached and read-only.
type TokenAuthenticator struct {
	Client kubernetes.Interface
	Reader client.Reader
}

func (a TokenAuthenticator) Authenticate(ctx context.Context, token string, enrollment journal.Enrollment) (Identity, error) {
	if ctx == nil || ctx.Err() != nil || a.Client == nil || a.Reader == nil || len(token) == 0 || len(token) > 16384 || strings.ContainsAny(token, " \t\r\n") {
		return Identity{}, fail("AuthenticationDenied")
	}
	review, err := a.Client.AuthenticationV1().TokenReviews().Create(ctx, &authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{
		Token: token, Audiences: []string{TokenAudience},
	}}, metav1.CreateOptions{})
	if err != nil || review == nil || !review.Status.Authenticated || review.Status.Error != "" || len(review.Status.Audiences) != 1 || review.Status.Audiences[0] != TokenAudience {
		return Identity{}, fail("AuthenticationDenied")
	}
	user := review.Status.User
	if user.Username != serviceAccountUser(enrollment.Namespace, enrollment.OperatorServiceAccount) || user.UID != enrollment.OperatorServiceAccountUID {
		return Identity{}, fail("IdentityMismatch")
	}
	podUID, podName := user.Extra[podUIDExtra], user.Extra[podNameExtra]
	if len(podUID) != 1 || len(podName) != 1 || podUID[0] == "" || podName[0] == "" {
		return Identity{}, fail("BoundPodRequired")
	}
	var namespace corev1.Namespace
	if a.Reader.Get(ctx, types.NamespacedName{Name: enrollment.Namespace}, &namespace) != nil || string(namespace.UID) != enrollment.NamespaceUID || !namespace.DeletionTimestamp.IsZero() {
		return Identity{}, fail("NamespaceReplaced")
	}
	var account corev1.ServiceAccount
	if a.Reader.Get(ctx, types.NamespacedName{Namespace: enrollment.Namespace, Name: enrollment.OperatorServiceAccount}, &account) != nil || string(account.UID) != enrollment.OperatorServiceAccountUID || !account.DeletionTimestamp.IsZero() {
		return Identity{}, fail("ServiceAccountReplaced")
	}
	var pod corev1.Pod
	if a.Reader.Get(ctx, types.NamespacedName{Namespace: enrollment.Namespace, Name: podName[0]}, &pod) != nil || string(pod.UID) != podUID[0] || pod.Spec.ServiceAccountName != enrollment.OperatorServiceAccount || !pod.DeletionTimestamp.IsZero() {
		return Identity{}, fail("PodReplaced")
	}
	return Identity{Namespace: enrollment.Namespace, ServiceAccount: enrollment.OperatorServiceAccount,
		ServiceAccountUID: enrollment.OperatorServiceAccountUID, PodName: podName[0], PodUID: podUID[0]}, nil
}

func serviceAccountUser(namespace, name string) string {
	return "system:serviceaccount:" + namespace + ":" + name
}
