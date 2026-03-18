.class public interface abstract Lcz/myskoda/api/bff/v1/UserApi;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcz/myskoda/api/bff/v1/UserApi$DefaultImpls;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0088\u0001\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0008f\u0018\u00002\u00020\u0001J \u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\u0016\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u0004H\u00a7@\u00a2\u0006\u0004\u0008\u0008\u0010\tJ \u0010\u000c\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00042\u0008\u0008\u0001\u0010\u000b\u001a\u00020\nH\u00a7@\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u0016\u0010\u000f\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u0004H\u00a7@\u00a2\u0006\u0004\u0008\u000f\u0010\tJ\"\u0010\u0012\u001a\u0008\u0012\u0004\u0012\u00020\u00110\u00042\n\u0008\u0003\u0010\u0010\u001a\u0004\u0018\u00010\nH\u00a7@\u00a2\u0006\u0004\u0008\u0012\u0010\rJ,\u0010\u0016\u001a\u0008\u0012\u0004\u0012\u00020\u00150\u00042\u0008\u0008\u0001\u0010\u0013\u001a\u00020\n2\n\u0008\u0003\u0010\u0014\u001a\u0004\u0018\u00010\nH\u00a7@\u00a2\u0006\u0004\u0008\u0016\u0010\u0017J\u0016\u0010\u0019\u001a\u0008\u0012\u0004\u0012\u00020\u00180\u0004H\u00a7@\u00a2\u0006\u0004\u0008\u0019\u0010\tJ\u0016\u0010\u001b\u001a\u0008\u0012\u0004\u0012\u00020\u001a0\u0004H\u00a7@\u00a2\u0006\u0004\u0008\u001b\u0010\tJ\u0016\u0010\u001d\u001a\u0008\u0012\u0004\u0012\u00020\u001c0\u0004H\u00a7@\u00a2\u0006\u0004\u0008\u001d\u0010\tJ \u0010 \u001a\u0008\u0012\u0004\u0012\u00020\u001f0\u00042\u0008\u0008\u0001\u0010\u001e\u001a\u00020\nH\u00a7@\u00a2\u0006\u0004\u0008 \u0010\rJ\u0016\u0010\"\u001a\u0008\u0012\u0004\u0012\u00020!0\u0004H\u00a7@\u00a2\u0006\u0004\u0008\"\u0010\tJ \u0010%\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00042\u0008\u0008\u0001\u0010$\u001a\u00020#H\u00a7@\u00a2\u0006\u0004\u0008%\u0010&J \u0010\'\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00042\u0008\u0008\u0001\u0010\u0013\u001a\u00020\nH\u00a7@\u00a2\u0006\u0004\u0008\'\u0010\rJ \u0010*\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00042\u0008\u0008\u0001\u0010)\u001a\u00020(H\u00a7@\u00a2\u0006\u0004\u0008*\u0010+J*\u0010/\u001a\u0008\u0012\u0004\u0012\u00020.0\u00042\u0008\u0008\u0001\u0010$\u001a\u00020#2\u0008\u0008\u0001\u0010-\u001a\u00020,H\u00a7@\u00a2\u0006\u0004\u0008/\u00100J*\u00103\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00042\u0008\u0008\u0001\u0010\u001e\u001a\u00020\n2\u0008\u0008\u0001\u00102\u001a\u000201H\u00a7@\u00a2\u0006\u0004\u00083\u00104J \u00107\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00042\u0008\u0008\u0001\u00106\u001a\u000205H\u00a7@\u00a2\u0006\u0004\u00087\u00108J \u0010:\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00042\u0008\u0008\u0001\u00109\u001a\u00020\u001cH\u00a7@\u00a2\u0006\u0004\u0008:\u0010;\u00a8\u0006<\u00c0\u0006\u0003"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/UserApi;",
        "",
        "Lcz/myskoda/api/bff/v1/NewVehicleDto;",
        "newVehicleDto",
        "Lretrofit2/Response;",
        "Llx0/b0;",
        "addVehicleToParkingAccount",
        "(Lcz/myskoda/api/bff/v1/NewVehicleDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "deleteParkingAccount",
        "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "",
        "xDeleteToken",
        "deleteUser",
        "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff/v1/ParkingAccountDto;",
        "getParkingAccount",
        "activeVehicleLicencePlate",
        "Lcz/myskoda/api/bff/v1/ParkingAccountSummaryDto;",
        "getParkingAccountPaymentSummary",
        "id",
        "sharedVin",
        "Ld01/v0;",
        "getProfilePicture",
        "(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff/v1/PayToServicesSupportedCountriesDto;",
        "getSupportedCountriesForPayToServices",
        "Lcz/myskoda/api/bff/v1/UserDto;",
        "getUser",
        "Lcz/myskoda/api/bff/v1/UserPreferencesDto;",
        "getUserPreferences",
        "consentId",
        "Lcz/myskoda/api/bff/v1/ConsentDto;",
        "getUsersConsent",
        "Lcz/myskoda/api/bff/v1/AgentIdDto;",
        "registerAgentId",
        "",
        "cardId",
        "removeCardFromParkingAccount",
        "(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "removeVehicleFromParkingAccount",
        "Lcz/myskoda/api/bff/v1/ParkingAccountDemandDto;",
        "parkingAccountDemandDto",
        "saveParkingAccount",
        "(Lcz/myskoda/api/bff/v1/ParkingAccountDemandDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff/v1/CardPatchDto;",
        "cardPatchDto",
        "Lcz/myskoda/api/bff/v1/CardDto;",
        "updateCard",
        "(JLcz/myskoda/api/bff/v1/CardPatchDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff/v1/ConsentDecisionDto;",
        "consentDecisionDto",
        "updateConsentDecision",
        "(Ljava/lang/String;Lcz/myskoda/api/bff/v1/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff/v1/ContactChannelDto;",
        "contactChannelDto",
        "updatePreferredContactChannel",
        "(Lcz/myskoda/api/bff/v1/ContactChannelDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "userPreferencesDto",
        "updateUserPreferences",
        "(Lcz/myskoda/api/bff/v1/UserPreferencesDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "bff-api_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static synthetic getParkingAccountPaymentSummary$default(Lcz/myskoda/api/bff/v1/UserApi;Ljava/lang/String;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    if-nez p4, :cond_1

    .line 2
    .line 3
    and-int/lit8 p3, p3, 0x1

    .line 4
    .line 5
    if-eqz p3, :cond_0

    .line 6
    .line 7
    const/4 p1, 0x0

    .line 8
    :cond_0
    invoke-interface {p0, p1, p2}, Lcz/myskoda/api/bff/v1/UserApi;->getParkingAccountPaymentSummary(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 14
    .line 15
    const-string p1, "Super calls with default arguments not supported in this target, function: getParkingAccountPaymentSummary"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public static synthetic getProfilePicture$default(Lcz/myskoda/api/bff/v1/UserApi;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    if-nez p5, :cond_1

    .line 2
    .line 3
    and-int/lit8 p4, p4, 0x2

    .line 4
    .line 5
    if-eqz p4, :cond_0

    .line 6
    .line 7
    const/4 p2, 0x0

    .line 8
    :cond_0
    invoke-interface {p0, p1, p2, p3}, Lcz/myskoda/api/bff/v1/UserApi;->getProfilePicture(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 14
    .line 15
    const-string p1, "Super calls with default arguments not supported in this target, function: getProfilePicture"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method


# virtual methods
.method public abstract addVehicleToParkingAccount(Lcz/myskoda/api/bff/v1/NewVehicleDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff/v1/NewVehicleDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff/v1/NewVehicleDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PUT;
        value = "api/v1/users/me/account/parking/vehicles"
    .end annotation
.end method

.method public abstract deleteParkingAccount(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/DELETE;
        value = "api/v1/users/me/account/parking"
    .end annotation
.end method

.method public abstract deleteUser(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Header;
            value = "X-delete-token"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/DELETE;
        value = "api/v1/users"
    .end annotation
.end method

.method public abstract getParkingAccount(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff/v1/ParkingAccountDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v1/users/me/account/parking"
    .end annotation
.end method

.method public abstract getParkingAccountPaymentSummary(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "activeVehicleLicencePlate"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff/v1/ParkingAccountSummaryDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v1/users/me/account/parking/summary"
    .end annotation
.end method

.method public abstract getProfilePicture(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "sharedVin"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Ld01/v0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v1/users/{id}/profile-picture"
    .end annotation
.end method

.method public abstract getSupportedCountriesForPayToServices(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff/v1/PayToServicesSupportedCountriesDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v1/users/pay-to-services/supported-countries"
    .end annotation
.end method

.method public abstract getUser(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff/v1/UserDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v1/users"
    .end annotation
.end method

.method public abstract getUserPreferences(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff/v1/UserPreferencesDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v1/users/preferences"
    .end annotation
.end method

.method public abstract getUsersConsent(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "consentId"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff/v1/ConsentDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v1/users/consents/{consentId}"
    .end annotation
.end method

.method public abstract registerAgentId(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff/v1/AgentIdDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v1/users/agent-id"
    .end annotation
.end method

.method public abstract removeCardFromParkingAccount(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # J
        .annotation runtime Lretrofit2/http/Path;
            value = "cardId"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(J",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/DELETE;
        value = "api/v1/users/me/account/parking/cards/{cardId}"
    .end annotation
.end method

.method public abstract removeVehicleFromParkingAccount(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/DELETE;
        value = "api/v1/users/me/account/parking/vehicles/{id}"
    .end annotation
.end method

.method public abstract saveParkingAccount(Lcz/myskoda/api/bff/v1/ParkingAccountDemandDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff/v1/ParkingAccountDemandDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff/v1/ParkingAccountDemandDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PUT;
        value = "api/v1/users/me/account/parking"
    .end annotation
.end method

.method public abstract updateCard(JLcz/myskoda/api/bff/v1/CardPatchDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # J
        .annotation runtime Lretrofit2/http/Path;
            value = "cardId"
        .end annotation
    .end param
    .param p3    # Lcz/myskoda/api/bff/v1/CardPatchDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(J",
            "Lcz/myskoda/api/bff/v1/CardPatchDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff/v1/CardDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PATCH;
        value = "api/v1/users/me/account/parking/cards/{cardId}"
    .end annotation
.end method

.method public abstract updateConsentDecision(Ljava/lang/String;Lcz/myskoda/api/bff/v1/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "consentId"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff/v1/ConsentDecisionDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff/v1/ConsentDecisionDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PUT;
        value = "api/v1/users/consents/{consentId}"
    .end annotation
.end method

.method public abstract updatePreferredContactChannel(Lcz/myskoda/api/bff/v1/ContactChannelDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff/v1/ContactChannelDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff/v1/ContactChannelDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PUT;
        value = "api/v1/users/preferred-contact-channel"
    .end annotation
.end method

.method public abstract updateUserPreferences(Lcz/myskoda/api/bff/v1/UserPreferencesDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff/v1/UserPreferencesDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff/v1/UserPreferencesDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PUT;
        value = "api/v1/users/preferences"
    .end annotation
.end method
