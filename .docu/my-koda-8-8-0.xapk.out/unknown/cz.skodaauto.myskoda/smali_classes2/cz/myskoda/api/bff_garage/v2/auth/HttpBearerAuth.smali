.class public final Lcz/myskoda/api/bff_garage/v2/auth/HttpBearerAuth;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/c0;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0018\u00002\u00020\u0001B\u001b\u0012\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u000f\u0010\u0007\u001a\u00020\u0002H\u0002\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u000f\u0010\t\u001a\u00020\u0002H\u0002\u00a2\u0006\u0004\u0008\t\u0010\u0008J\u0017\u0010\r\u001a\u00020\u000c2\u0006\u0010\u000b\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\r\u0010\u000eR\u0016\u0010\u0003\u001a\u00020\u00028\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008\u0003\u0010\u000fR\"\u0010\u0004\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0004\u0010\u000f\u001a\u0004\u0008\u0010\u0010\u0008\"\u0004\u0008\u0011\u0010\u0012\u00a8\u0006\u0013"
    }
    d2 = {
        "Lcz/myskoda/api/bff_garage/v2/auth/HttpBearerAuth;",
        "Ld01/c0;",
        "",
        "schema",
        "bearerToken",
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        "headerValue",
        "()Ljava/lang/String;",
        "upperCaseBearer",
        "Ld01/b0;",
        "chain",
        "Ld01/t0;",
        "intercept",
        "(Ld01/b0;)Ld01/t0;",
        "Ljava/lang/String;",
        "getBearerToken",
        "setBearerToken",
        "(Ljava/lang/String;)V",
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


# instance fields
.field private bearerToken:Ljava/lang/String;

.field private schema:Ljava/lang/String;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    const/4 v1, 0x3

    invoke-direct {p0, v0, v0, v1, v0}, Lcz/myskoda/api/bff_garage/v2/auth/HttpBearerAuth;-><init>(Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    const-string v0, "schema"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "bearerToken"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcz/myskoda/api/bff_garage/v2/auth/HttpBearerAuth;->schema:Ljava/lang/String;

    .line 4
    iput-object p2, p0, Lcz/myskoda/api/bff_garage/v2/auth/HttpBearerAuth;->bearerToken:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p4, p3, 0x1

    .line 5
    const-string v0, ""

    if-eqz p4, :cond_0

    move-object p1, v0

    :cond_0
    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_1

    move-object p2, v0

    :cond_1
    invoke-direct {p0, p1, p2}, Lcz/myskoda/api/bff_garage/v2/auth/HttpBearerAuth;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method private final headerValue()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_garage/v2/auth/HttpBearerAuth;->schema:Ljava/lang/String;

    .line 2
    .line 3
    invoke-static {v0}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    invoke-direct {p0}, Lcz/myskoda/api/bff_garage/v2/auth/HttpBearerAuth;->upperCaseBearer()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/auth/HttpBearerAuth;->bearerToken:Ljava/lang/String;

    .line 14
    .line 15
    const-string v1, " "

    .line 16
    .line 17
    invoke-static {v0, v1, p0}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :cond_0
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/auth/HttpBearerAuth;->bearerToken:Ljava/lang/String;

    .line 23
    .line 24
    return-object p0
.end method

.method private final upperCaseBearer()Ljava/lang/String;
    .locals 4

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_garage/v2/auth/HttpBearerAuth;->schema:Ljava/lang/String;

    .line 2
    .line 3
    sget-object v1, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 4
    .line 5
    const-string v2, "toLowerCase(...)"

    .line 6
    .line 7
    const-string v3, "bearer"

    .line 8
    .line 9
    invoke-static {v0, v2, v3, v1}, Lkx/a;->A(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Locale;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const-string p0, "Bearer"

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/auth/HttpBearerAuth;->schema:Ljava/lang/String;

    .line 19
    .line 20
    return-object p0
.end method


# virtual methods
.method public final getBearerToken()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/auth/HttpBearerAuth;->bearerToken:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public intercept(Ld01/b0;)Ld01/t0;
    .locals 3

    .line 1
    const-string v0, "chain"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Li01/f;

    .line 7
    .line 8
    iget-object v0, p1, Li01/f;->e:Ld01/k0;

    .line 9
    .line 10
    iget-object v1, v0, Ld01/k0;->c:Ld01/y;

    .line 11
    .line 12
    const-string v2, "Authorization"

    .line 13
    .line 14
    invoke-virtual {v1, v2}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    if-nez v1, :cond_0

    .line 19
    .line 20
    iget-object v1, p0, Lcz/myskoda/api/bff_garage/v2/auth/HttpBearerAuth;->bearerToken:Ljava/lang/String;

    .line 21
    .line 22
    invoke-static {v1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-nez v1, :cond_0

    .line 27
    .line 28
    invoke-virtual {v0}, Ld01/k0;->b()Ld01/j0;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-direct {p0}, Lcz/myskoda/api/bff_garage/v2/auth/HttpBearerAuth;->headerValue()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-static {v0, v2, p0, v0}, Lp3/m;->c(Ld01/j0;Ljava/lang/String;Ljava/lang/String;Ld01/j0;)Ld01/k0;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    :cond_0
    invoke-virtual {p1, v0}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0
.end method

.method public final setBearerToken(Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcz/myskoda/api/bff_garage/v2/auth/HttpBearerAuth;->bearerToken:Ljava/lang/String;

    .line 7
    .line 8
    return-void
.end method
