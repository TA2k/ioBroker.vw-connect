.class public interface abstract Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$DefaultImpls;,
        Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$FilterModeGetLoyaltyMemberProfile;,
        Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$TypeGetBadgeDetail;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00a2\u0001\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0006\u0008f\u0018\u00002\u00020\u0001:\u0002DEJ*\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\u00070\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0005\u001a\u00020\u0004H\u00a7@\u00a2\u0006\u0004\u0008\u0008\u0010\tJ*\u0010\u000c\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\n\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u000c\u0010\rJ \u0010\u000e\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ4\u0010\u0013\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0010\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0012\u001a\u00020\u0011H\u00a7@\u00a2\u0006\u0004\u0008\u0013\u0010\u0014J4\u0010\u0018\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0015\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0017\u001a\u00020\u0016H\u00a7@\u00a2\u0006\u0004\u0008\u0018\u0010\u0019J\"\u0010\u001d\u001a\u0008\u0012\u0004\u0012\u00020\u001c0\u00062\n\u0008\u0003\u0010\u001b\u001a\u0004\u0018\u00010\u001aH\u00a7@\u00a2\u0006\u0004\u0008\u001d\u0010\u001eJ6\u0010\"\u001a\u0008\u0012\u0004\u0012\u00020!0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\n\u001a\u00020\u00022\n\u0008\u0003\u0010 \u001a\u0004\u0018\u00010\u001fH\u00a7@\u00a2\u0006\u0004\u0008\"\u0010#J \u0010%\u001a\u0008\u0012\u0004\u0012\u00020$0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008%\u0010\u000fJ,\u0010(\u001a\u0008\u0012\u0004\u0012\u00020\'0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\n\u0008\u0003\u0010&\u001a\u0004\u0018\u00010\u0002H\u00a7@\u00a2\u0006\u0004\u0008(\u0010\rJ \u0010*\u001a\u0008\u0012\u0004\u0012\u00020)0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008*\u0010\u000fJ8\u0010.\u001a\u0008\u0012\u0004\u0012\u00020-0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\n\u0008\u0003\u0010&\u001a\u0004\u0018\u00010\u00022\n\u0008\u0003\u0010,\u001a\u0004\u0018\u00010+H\u00a7@\u00a2\u0006\u0004\u0008.\u0010/J \u00101\u001a\u0008\u0012\u0004\u0012\u0002000\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u00081\u0010\u000fJ \u00103\u001a\u0008\u0012\u0004\u0012\u0002020\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u00083\u0010\u000fJ\u0016\u00105\u001a\u0008\u0012\u0004\u0012\u0002040\u0006H\u00a7@\u00a2\u0006\u0004\u00085\u00106J \u00108\u001a\u0008\u0012\u0004\u0012\u0002070\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u00088\u0010\u000fJ \u00109\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u00089\u0010\u000fJ*\u0010:\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0010\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008:\u0010\rJ*\u0010=\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010<\u001a\u00020;H\u00a7@\u00a2\u0006\u0004\u0008=\u0010>J4\u0010B\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010?\u001a\u00020\u00022\u0008\u0008\u0001\u0010A\u001a\u00020@H\u00a7@\u00a2\u0006\u0004\u0008B\u0010C\u00a8\u0006F\u00c0\u0006\u0003"
    }
    d2 = {
        "Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;",
        "",
        "",
        "id",
        "Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardRequestDto;",
        "claimRewardRequestDto",
        "Lretrofit2/Response;",
        "Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardResponseDto;",
        "claimReward",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "badgeId",
        "Llx0/b0;",
        "collectBadge",
        "(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "completeDailyCheckIn",
        "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "challengeId",
        "Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeEnrollmentRequestDto;",
        "challengeEnrollmentRequestDto",
        "enrollUserIntoLoyaltyChallenge",
        "(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeEnrollmentRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "gameId",
        "Lcz/myskoda/api/bff_loyalty_program/v2/GameEnrollmentRequestDto;",
        "gameEnrollmentRequestDto",
        "enrollUserIntoLoyaltyGame",
        "(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/GameEnrollmentRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_loyalty_program/v2/MemberEnrollmentRequestDto;",
        "memberEnrollmentRequestDto",
        "Lcz/myskoda/api/bff_loyalty_program/v2/MemberEnrollmentResponseDto;",
        "enrollUserIntoLoyaltyProgram",
        "(Lcz/myskoda/api/bff_loyalty_program/v2/MemberEnrollmentRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$TypeGetBadgeDetail;",
        "type",
        "Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDetailDto;",
        "getBadgeDetail",
        "(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$TypeGetBadgeDetail;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_loyalty_program/v2/BadgesResponseDto;",
        "getLoyaltyMemberBadges",
        "vin",
        "Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;",
        "getLoyaltyMemberChallenges",
        "Lcz/myskoda/api/bff_loyalty_program/v2/GamesResponseDto;",
        "getLoyaltyMemberGames",
        "Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$FilterModeGetLoyaltyMemberProfile;",
        "filterMode",
        "Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfileDto;",
        "getLoyaltyMemberProfile",
        "(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$FilterModeGetLoyaltyMemberProfile;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_loyalty_program/v2/RewardsDto;",
        "getLoyaltyMemberRewards",
        "Lcz/myskoda/api/bff_loyalty_program/v2/TransactionsDto;",
        "getLoyaltyMemberTransactions",
        "Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramDetailsDto;",
        "getLoyaltyProgramDetails",
        "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_loyalty_program/v2/SalesforceContactDto;",
        "getLoyaltySalesforceContact",
        "removeLoyaltyMemberProfile",
        "unsubscribeUserFromLoyaltyChallenge",
        "Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfilePatchDto;",
        "memberProfilePatchDto",
        "updateLoyaltyMemberProfile",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfilePatchDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "rewardId",
        "Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyRewardPatchDto;",
        "loyaltyRewardPatchDto",
        "updateLoyaltyMemberReward",
        "(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyRewardPatchDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "TypeGetBadgeDetail",
        "FilterModeGetLoyaltyMemberProfile",
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
.method public static synthetic enrollUserIntoLoyaltyProgram$default(Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;Lcz/myskoda/api/bff_loyalty_program/v2/MemberEnrollmentRequestDto;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
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
    invoke-interface {p0, p1, p2}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;->enrollUserIntoLoyaltyProgram(Lcz/myskoda/api/bff_loyalty_program/v2/MemberEnrollmentRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    const-string p1, "Super calls with default arguments not supported in this target, function: enrollUserIntoLoyaltyProgram"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public static synthetic getBadgeDetail$default(Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$TypeGetBadgeDetail;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    if-nez p6, :cond_1

    .line 2
    .line 3
    and-int/lit8 p5, p5, 0x4

    .line 4
    .line 5
    if-eqz p5, :cond_0

    .line 6
    .line 7
    sget-object p3, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$TypeGetBadgeDetail;->ACHIEVEMENT:Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$TypeGetBadgeDetail;

    .line 8
    .line 9
    :cond_0
    invoke-interface {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;->getBadgeDetail(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$TypeGetBadgeDetail;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    const-string p1, "Super calls with default arguments not supported in this target, function: getBadgeDetail"

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0
.end method

.method public static synthetic getLoyaltyMemberChallenges$default(Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
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
    invoke-interface {p0, p1, p2, p3}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;->getLoyaltyMemberChallenges(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    const-string p1, "Super calls with default arguments not supported in this target, function: getLoyaltyMemberChallenges"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public static synthetic getLoyaltyMemberProfile$default(Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$FilterModeGetLoyaltyMemberProfile;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    if-nez p6, :cond_2

    .line 2
    .line 3
    and-int/lit8 p6, p5, 0x2

    .line 4
    .line 5
    if-eqz p6, :cond_0

    .line 6
    .line 7
    const/4 p2, 0x0

    .line 8
    :cond_0
    and-int/lit8 p5, p5, 0x4

    .line 9
    .line 10
    if-eqz p5, :cond_1

    .line 11
    .line 12
    sget-object p3, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$FilterModeGetLoyaltyMemberProfile;->NONE:Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$FilterModeGetLoyaltyMemberProfile;

    .line 13
    .line 14
    :cond_1
    invoke-interface {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;->getLoyaltyMemberProfile(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$FilterModeGetLoyaltyMemberProfile;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    const-string p1, "Super calls with default arguments not supported in this target, function: getLoyaltyMemberProfile"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0
.end method


# virtual methods
.method public abstract claimReward(Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardResponseDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/loyalty-program/members/{id}/rewards"
    .end annotation
.end method

.method public abstract collectBadge(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "badgeId"
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
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/loyalty-program/members/{id}/badges/{badgeId}/collect-badge"
    .end annotation
.end method

.method public abstract completeDailyCheckIn(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/loyalty-program/members/{id}/daily-check-in"
    .end annotation
.end method

.method public abstract enrollUserIntoLoyaltyChallenge(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeEnrollmentRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "challengeId"
        .end annotation
    .end param
    .param p3    # Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeEnrollmentRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeEnrollmentRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PUT;
        value = "api/v2/loyalty-program/members/{id}/challenges/{challengeId}/enrollment"
    .end annotation
.end method

.method public abstract enrollUserIntoLoyaltyGame(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/GameEnrollmentRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "gameId"
        .end annotation
    .end param
    .param p3    # Lcz/myskoda/api/bff_loyalty_program/v2/GameEnrollmentRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_loyalty_program/v2/GameEnrollmentRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PUT;
        value = "api/v2/loyalty-program/members/{id}/games/{gameId}/enrollment"
    .end annotation
.end method

.method public abstract enrollUserIntoLoyaltyProgram(Lcz/myskoda/api/bff_loyalty_program/v2/MemberEnrollmentRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff_loyalty_program/v2/MemberEnrollmentRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_loyalty_program/v2/MemberEnrollmentRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_loyalty_program/v2/MemberEnrollmentResponseDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/loyalty-program/members"
    .end annotation
.end method

.method public abstract getBadgeDetail(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$TypeGetBadgeDetail;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "badgeId"
        .end annotation
    .end param
    .param p3    # Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$TypeGetBadgeDetail;
        .annotation runtime Lretrofit2/http/Query;
            value = "type"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$TypeGetBadgeDetail;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDetailDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/loyalty-program/members/{id}/badges/{badgeId}"
    .end annotation
.end method

.method public abstract getLoyaltyMemberBadges(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
            "Lcz/myskoda/api/bff_loyalty_program/v2/BadgesResponseDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/loyalty-program/members/{id}/badges"
    .end annotation
.end method

.method public abstract getLoyaltyMemberChallenges(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "vin"
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
            "Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/loyalty-program/members/{id}/challenges"
    .end annotation
.end method

.method public abstract getLoyaltyMemberGames(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
            "Lcz/myskoda/api/bff_loyalty_program/v2/GamesResponseDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/loyalty-program/members/{id}/games"
    .end annotation
.end method

.method public abstract getLoyaltyMemberProfile(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$FilterModeGetLoyaltyMemberProfile;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "vin"
        .end annotation
    .end param
    .param p3    # Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$FilterModeGetLoyaltyMemberProfile;
        .annotation runtime Lretrofit2/http/Query;
            value = "filterMode"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$FilterModeGetLoyaltyMemberProfile;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfileDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/loyalty-program/members/{id}"
    .end annotation
.end method

.method public abstract getLoyaltyMemberRewards(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
            "Lcz/myskoda/api/bff_loyalty_program/v2/RewardsDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/loyalty-program/members/{id}/rewards"
    .end annotation
.end method

.method public abstract getLoyaltyMemberTransactions(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
            "Lcz/myskoda/api/bff_loyalty_program/v2/TransactionsDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/loyalty-program/members/{id}/transactions"
    .end annotation
.end method

.method public abstract getLoyaltyProgramDetails(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramDetailsDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/loyalty-program/details"
    .end annotation
.end method

.method public abstract getLoyaltySalesforceContact(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
            "Lcz/myskoda/api/bff_loyalty_program/v2/SalesforceContactDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/loyalty-program/salesforce-contacts/{id}"
    .end annotation
.end method

.method public abstract removeLoyaltyMemberProfile(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
        value = "api/v2/loyalty-program/members/{id}"
    .end annotation
.end method

.method public abstract unsubscribeUserFromLoyaltyChallenge(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "challengeId"
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
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/DELETE;
        value = "api/v2/loyalty-program/members/{id}/challenges/{challengeId}/enrollment"
    .end annotation
.end method

.method public abstract updateLoyaltyMemberProfile(Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfilePatchDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfilePatchDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfilePatchDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PATCH;
        value = "api/v2/loyalty-program/members/{id}"
    .end annotation
.end method

.method public abstract updateLoyaltyMemberReward(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyRewardPatchDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "rewardId"
        .end annotation
    .end param
    .param p3    # Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyRewardPatchDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyRewardPatchDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PATCH;
        value = "api/v2/loyalty-program/members/{id}/rewards/{rewardId}"
    .end annotation
.end method
