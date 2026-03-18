.class public final Lhw0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Low0/f;


# static fields
.field public static final d:Lhw0/j;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lhw0/j;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lhw0/j;->d:Lhw0/j;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Low0/e;)Z
    .locals 4

    .line 1
    const-string p0, "contentType"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Low0/b;->a:Low0/e;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Low0/e;->q(Low0/e;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const/4 v1, 0x1

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_0
    iget-object v0, p1, Lh/w;->c:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Ljava/util/List;

    .line 19
    .line 20
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    new-instance v0, Low0/e;

    .line 28
    .line 29
    iget-object v2, p1, Low0/e;->d:Ljava/lang/String;

    .line 30
    .line 31
    iget-object p1, p1, Low0/e;->e:Ljava/lang/String;

    .line 32
    .line 33
    sget-object v3, Lmx0/s;->d:Lmx0/s;

    .line 34
    .line 35
    invoke-direct {v0, v2, p1, v3}, Low0/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 36
    .line 37
    .line 38
    move-object p1, v0

    .line 39
    :goto_0
    invoke-virtual {p1}, Lh/w;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const-string p0, "application/"

    .line 47
    .line 48
    invoke-static {p1, p0, v1}, Lly0/p;->Z(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    if-eqz p0, :cond_2

    .line 53
    .line 54
    const-string p0, "+json"

    .line 55
    .line 56
    invoke-static {p1, p0, v1}, Lly0/w;->o(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    if-eqz p0, :cond_2

    .line 61
    .line 62
    :goto_1
    return v1

    .line 63
    :cond_2
    const/4 p0, 0x0

    .line 64
    return p0
.end method
