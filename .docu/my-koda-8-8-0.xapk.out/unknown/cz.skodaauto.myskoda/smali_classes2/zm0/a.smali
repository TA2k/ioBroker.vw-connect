.class public abstract Lzm0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lcz/skodaauto/myskoda/library/operationrequest/data/VersionDto;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcz/skodaauto/myskoda/library/operationrequest/data/VersionDto;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lcz/skodaauto/myskoda/library/operationrequest/data/VersionDto;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lzm0/a;->a:Lcz/skodaauto/myskoda/library/operationrequest/data/VersionDto;

    .line 8
    .line 9
    return-void
.end method

.method public static final a(Ldc0/a;)Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;
    .locals 6

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ldc0/a;->b:Ljava/lang/String;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    if-eqz p0, :cond_1

    .line 10
    .line 11
    sget-object v1, Lzm0/d;->a:Llx0/q;

    .line 12
    .line 13
    invoke-virtual {v1}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    const-string v3, "getValue(...)"

    .line 18
    .line 19
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    check-cast v2, Lcom/squareup/moshi/Moshi;

    .line 23
    .line 24
    sget-object v4, Lax/b;->a:Ljava/util/Set;

    .line 25
    .line 26
    const-class v5, Lcz/skodaauto/myskoda/library/operationrequest/data/VersionDto;

    .line 27
    .line 28
    invoke-virtual {v2, v5, v4, v0}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    invoke-virtual {v2, p0}, Lcom/squareup/moshi/JsonAdapter;->b(Ljava/lang/String;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    check-cast v2, Lcz/skodaauto/myskoda/library/operationrequest/data/VersionDto;

    .line 37
    .line 38
    sget-object v5, Lzm0/a;->a:Lcz/skodaauto/myskoda/library/operationrequest/data/VersionDto;

    .line 39
    .line 40
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    if-eqz v2, :cond_0

    .line 45
    .line 46
    invoke-virtual {v1}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    check-cast v1, Lcom/squareup/moshi/Moshi;

    .line 54
    .line 55
    const-class v2, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;

    .line 56
    .line 57
    invoke-virtual {v1, v2, v4, v0}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    invoke-virtual {v0, p0}, Lcom/squareup/moshi/JsonAdapter;->b(Ljava/lang/String;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;

    .line 66
    .line 67
    return-object p0

    .line 68
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 69
    .line 70
    const-string v0, "Unsupported message version."

    .line 71
    .line 72
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw p0

    .line 76
    :cond_1
    return-object v0
.end method
