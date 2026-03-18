.class public abstract Lwb0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lwb0/b;->a:Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;

    .line 8
    .line 9
    return-void
.end method

.method public static final a(Ldc0/a;)Lcz/skodaauto/myskoda/library/asyncevent/data/AsyncEventDto;
    .locals 4

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
    invoke-static {}, Lwb0/c;->a()Lcom/squareup/moshi/Moshi;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    sget-object v2, Lax/b;->a:Ljava/util/Set;

    .line 16
    .line 17
    const-class v3, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;

    .line 18
    .line 19
    invoke-virtual {v1, v3, v2, v0}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-virtual {v1, p0}, Lcom/squareup/moshi/JsonAdapter;->b(Ljava/lang/String;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    check-cast v1, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;

    .line 28
    .line 29
    sget-object v3, Lwb0/b;->a:Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;

    .line 30
    .line 31
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_0

    .line 36
    .line 37
    invoke-static {}, Lwb0/c;->a()Lcom/squareup/moshi/Moshi;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    const-class v3, Lcz/skodaauto/myskoda/library/asyncevent/data/AsyncEventDto;

    .line 42
    .line 43
    invoke-virtual {v1, v3, v2, v0}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-virtual {v0, p0}, Lcom/squareup/moshi/JsonAdapter;->b(Ljava/lang/String;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    check-cast p0, Lcz/skodaauto/myskoda/library/asyncevent/data/AsyncEventDto;

    .line 52
    .line 53
    return-object p0

    .line 54
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 55
    .line 56
    const-string v0, "Unsupported message version."

    .line 57
    .line 58
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw p0

    .line 62
    :cond_1
    return-object v0
.end method
