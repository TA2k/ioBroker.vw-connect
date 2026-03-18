.class public interface abstract Lcz/myskoda/api/bff_consents/v2/ConsentsApi;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcz/myskoda/api/bff_consents/v2/ConsentsApi$DefaultImpls;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\\\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\t\u0008f\u0018\u00002\u00020\u0001J\u0016\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J \u0010\t\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u00022\u0008\u0008\u0001\u0010\u0007\u001a\u00020\u0006H\u00a7@\u00a2\u0006\u0004\u0008\t\u0010\nJ\u0016\u0010\u000c\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u000c\u0010\u0005J\u0016\u0010\u000e\u001a\u0008\u0012\u0004\u0012\u00020\r0\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u000e\u0010\u0005J\u0016\u0010\u0010\u001a\u0008\u0012\u0004\u0012\u00020\u000f0\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0010\u0010\u0005J\u0016\u0010\u0012\u001a\u0008\u0012\u0004\u0012\u00020\u00110\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0012\u0010\u0005J\"\u0010\u0015\u001a\u0008\u0012\u0004\u0012\u00020\u00140\u00022\n\u0008\u0003\u0010\u0013\u001a\u0004\u0018\u00010\u0006H\u00a7@\u00a2\u0006\u0004\u0008\u0015\u0010\nJ\u0016\u0010\u0017\u001a\u0008\u0012\u0004\u0012\u00020\u00160\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0017\u0010\u0005J\u0016\u0010\u0019\u001a\u0008\u0012\u0004\u0012\u00020\u00180\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0019\u0010\u0005J,\u0010\u001d\u001a\u0008\u0012\u0004\u0012\u00020\u001c0\u00022\u0008\u0008\u0001\u0010\u0007\u001a\u00020\u00062\n\u0008\u0003\u0010\u001b\u001a\u0004\u0018\u00010\u001aH\u00a7@\u00a2\u0006\u0004\u0008\u001d\u0010\u001eJ\"\u0010\u001f\u001a\u0008\u0012\u0004\u0012\u00020\u001c0\u00022\n\u0008\u0003\u0010\u001b\u001a\u0004\u0018\u00010\u001aH\u00a7@\u00a2\u0006\u0004\u0008\u001f\u0010 J\"\u0010!\u001a\u0008\u0012\u0004\u0012\u00020\u001c0\u00022\n\u0008\u0003\u0010\u001b\u001a\u0004\u0018\u00010\u001aH\u00a7@\u00a2\u0006\u0004\u0008!\u0010 J\"\u0010\"\u001a\u0008\u0012\u0004\u0012\u00020\u001c0\u00022\n\u0008\u0003\u0010\u001b\u001a\u0004\u0018\u00010\u001aH\u00a7@\u00a2\u0006\u0004\u0008\"\u0010 J.\u0010#\u001a\u0008\u0012\u0004\u0012\u00020\u001c0\u00022\n\u0008\u0003\u0010\u0013\u001a\u0004\u0018\u00010\u00062\n\u0008\u0003\u0010\u001b\u001a\u0004\u0018\u00010\u001aH\u00a7@\u00a2\u0006\u0004\u0008#\u0010\u001eJ\"\u0010$\u001a\u0008\u0012\u0004\u0012\u00020\u001c0\u00022\n\u0008\u0003\u0010\u001b\u001a\u0004\u0018\u00010\u001aH\u00a7@\u00a2\u0006\u0004\u0008$\u0010 \u00a8\u0006%\u00c0\u0006\u0003"
    }
    d2 = {
        "Lcz/myskoda/api/bff_consents/v2/ConsentsApi;",
        "",
        "Lretrofit2/Response;",
        "Lcz/myskoda/api/bff_consents/v2/AccessibilityStatementDto;",
        "getAccessibilityStatement",
        "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "",
        "vin",
        "Lcz/myskoda/api/bff_consents/v2/LinkConsentDto;",
        "getEprivacyConsent",
        "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_consents/v2/EuDataActDto;",
        "getEuDataAct",
        "Lcz/myskoda/api/bff_consents/v2/LocationAccessConsentDto;",
        "getLocationAccessConsent",
        "Lcz/myskoda/api/bff_consents/v2/LoyaltyProgramConsentDto;",
        "getLoyaltyProgramConsent",
        "Lcz/myskoda/api/bff_consents/v2/MandatoryConsentDto;",
        "getMandatoryConsent",
        "id",
        "Lcz/myskoda/api/bff_consents/v2/MarketingConsentDto;",
        "getMarketingConsent",
        "Lcz/myskoda/api/bff_consents/v2/TermsOfUseConsentDto;",
        "getTermsOfUseConsent",
        "Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;",
        "getThirdPartyOffersConsent",
        "Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;",
        "consentDecisionDto",
        "Llx0/b0;",
        "setEprivacyConsentDecision",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "setLocationAccessConsentDecision",
        "(Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "setLoyaltyProgramConsentDecision",
        "setMandatoryConsentDecision",
        "setMarketingConsentDecision",
        "setThirdPartyOffersConsentDecision",
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
.method public static synthetic getMarketingConsent$default(Lcz/myskoda/api/bff_consents/v2/ConsentsApi;Ljava/lang/String;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
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
    const-string p1, "MARKETING_CONSENT_GENERIC"

    .line 8
    .line 9
    :cond_0
    invoke-interface {p0, p1, p2}, Lcz/myskoda/api/bff_consents/v2/ConsentsApi;->getMarketingConsent(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 15
    .line 16
    const-string p1, "Super calls with default arguments not supported in this target, function: getMarketingConsent"

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0
.end method

.method public static synthetic setEprivacyConsentDecision$default(Lcz/myskoda/api/bff_consents/v2/ConsentsApi;Ljava/lang/String;Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
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
    invoke-interface {p0, p1, p2, p3}, Lcz/myskoda/api/bff_consents/v2/ConsentsApi;->setEprivacyConsentDecision(Ljava/lang/String;Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    const-string p1, "Super calls with default arguments not supported in this target, function: setEprivacyConsentDecision"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public static synthetic setLocationAccessConsentDecision$default(Lcz/myskoda/api/bff_consents/v2/ConsentsApi;Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
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
    invoke-interface {p0, p1, p2}, Lcz/myskoda/api/bff_consents/v2/ConsentsApi;->setLocationAccessConsentDecision(Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    const-string p1, "Super calls with default arguments not supported in this target, function: setLocationAccessConsentDecision"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public static synthetic setLoyaltyProgramConsentDecision$default(Lcz/myskoda/api/bff_consents/v2/ConsentsApi;Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
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
    invoke-interface {p0, p1, p2}, Lcz/myskoda/api/bff_consents/v2/ConsentsApi;->setLoyaltyProgramConsentDecision(Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    const-string p1, "Super calls with default arguments not supported in this target, function: setLoyaltyProgramConsentDecision"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public static synthetic setMandatoryConsentDecision$default(Lcz/myskoda/api/bff_consents/v2/ConsentsApi;Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
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
    invoke-interface {p0, p1, p2}, Lcz/myskoda/api/bff_consents/v2/ConsentsApi;->setMandatoryConsentDecision(Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    const-string p1, "Super calls with default arguments not supported in this target, function: setMandatoryConsentDecision"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public static synthetic setMarketingConsentDecision$default(Lcz/myskoda/api/bff_consents/v2/ConsentsApi;Ljava/lang/String;Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    if-nez p5, :cond_2

    .line 2
    .line 3
    and-int/lit8 p5, p4, 0x1

    .line 4
    .line 5
    if-eqz p5, :cond_0

    .line 6
    .line 7
    const-string p1, "MARKETING_CONSENT_GENERIC"

    .line 8
    .line 9
    :cond_0
    and-int/lit8 p4, p4, 0x2

    .line 10
    .line 11
    if-eqz p4, :cond_1

    .line 12
    .line 13
    const/4 p2, 0x0

    .line 14
    :cond_1
    invoke-interface {p0, p1, p2, p3}, Lcz/myskoda/api/bff_consents/v2/ConsentsApi;->setMarketingConsentDecision(Ljava/lang/String;Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_2
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 20
    .line 21
    const-string p1, "Super calls with default arguments not supported in this target, function: setMarketingConsentDecision"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0
.end method

.method public static synthetic setThirdPartyOffersConsentDecision$default(Lcz/myskoda/api/bff_consents/v2/ConsentsApi;Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
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
    invoke-interface {p0, p1, p2}, Lcz/myskoda/api/bff_consents/v2/ConsentsApi;->setThirdPartyOffersConsentDecision(Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    const-string p1, "Super calls with default arguments not supported in this target, function: setThirdPartyOffersConsentDecision"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method


# virtual methods
.method public abstract getAccessibilityStatement(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_consents/v2/AccessibilityStatementDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/consents/accessibility-statement"
    .end annotation
.end method

.method public abstract getEprivacyConsent(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_consents/v2/LinkConsentDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/consents/eprivacy/{vin}"
    .end annotation
.end method

.method public abstract getEuDataAct(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_consents/v2/EuDataActDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/consents/eu-data-act"
    .end annotation
.end method

.method public abstract getLocationAccessConsent(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_consents/v2/LocationAccessConsentDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/consents/location-access"
    .end annotation
.end method

.method public abstract getLoyaltyProgramConsent(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_consents/v2/LoyaltyProgramConsentDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/consents/loyalty-program"
    .end annotation
.end method

.method public abstract getMandatoryConsent(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_consents/v2/MandatoryConsentDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/consents/mandatory"
    .end annotation
.end method

.method public abstract getMarketingConsent(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
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
            "Lcz/myskoda/api/bff_consents/v2/MarketingConsentDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/consents/marketing"
    .end annotation
.end method

.method public abstract getTermsOfUseConsent(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_consents/v2/TermsOfUseConsentDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/consents/terms-of-use"
    .end annotation
.end method

.method public abstract getThirdPartyOffersConsent(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_consents/v2/ThirdPartyOffersConsentDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/consents/third-party-offers"
    .end annotation
.end method

.method public abstract setEprivacyConsentDecision(Ljava/lang/String;Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PATCH;
        value = "api/v2/consents/eprivacy/{vin}"
    .end annotation
.end method

.method public abstract setLocationAccessConsentDecision(Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PATCH;
        value = "api/v2/consents/location-access"
    .end annotation
.end method

.method public abstract setLoyaltyProgramConsentDecision(Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PATCH;
        value = "api/v2/consents/loyalty-program"
    .end annotation
.end method

.method public abstract setMandatoryConsentDecision(Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PATCH;
        value = "api/v2/consents/mandatory"
    .end annotation
.end method

.method public abstract setMarketingConsentDecision(Ljava/lang/String;Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "id"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PATCH;
        value = "api/v2/consents/marketing"
    .end annotation
.end method

.method public abstract setThirdPartyOffersConsentDecision(Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_consents/v2/ConsentDecisionDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PATCH;
        value = "api/v2/consents/third-party-offers"
    .end annotation
.end method
