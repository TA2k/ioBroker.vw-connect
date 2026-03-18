.class public final Lhu/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lhu/a1;

.field public final b:Lhu/b1;


# direct methods
.method public constructor <init>(Lhu/a1;Lhu/b1;)V
    .locals 1

    .line 1
    const-string v0, "timeProvider"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "uuidGenerator"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lhu/p0;->a:Lhu/a1;

    .line 15
    .line 16
    iput-object p2, p0, Lhu/p0;->b:Lhu/b1;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a(Lhu/j0;)Lhu/j0;
    .locals 9

    .line 1
    iget-object v0, p0, Lhu/p0;->b:Lhu/b1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    const-string v1, "randomUUID(...)"

    .line 11
    .line 12
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    const-string v1, "toString(...)"

    .line 20
    .line 21
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    const-string v2, "-"

    .line 26
    .line 27
    const-string v3, ""

    .line 28
    .line 29
    invoke-static {v1, v0, v2, v3}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    sget-object v2, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 34
    .line 35
    invoke-virtual {v0, v2}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    const-string v0, "toLowerCase(...)"

    .line 40
    .line 41
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    new-instance v3, Lhu/j0;

    .line 45
    .line 46
    if-eqz p1, :cond_1

    .line 47
    .line 48
    iget-object v0, p1, Lhu/j0;->b:Ljava/lang/String;

    .line 49
    .line 50
    if-nez v0, :cond_0

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_0
    move-object v5, v0

    .line 54
    goto :goto_1

    .line 55
    :cond_1
    :goto_0
    move-object v5, v4

    .line 56
    :goto_1
    if-eqz p1, :cond_2

    .line 57
    .line 58
    iget p1, p1, Lhu/j0;->c:I

    .line 59
    .line 60
    add-int/lit8 v1, p1, 0x1

    .line 61
    .line 62
    :cond_2
    move v6, v1

    .line 63
    iget-object p0, p0, Lhu/p0;->a:Lhu/a1;

    .line 64
    .line 65
    invoke-virtual {p0}, Lhu/a1;->a()Lhu/z0;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    iget-wide v7, p0, Lhu/z0;->b:J

    .line 70
    .line 71
    invoke-direct/range {v3 .. v8}, Lhu/j0;-><init>(Ljava/lang/String;Ljava/lang/String;IJ)V

    .line 72
    .line 73
    .line 74
    return-object v3
.end method
