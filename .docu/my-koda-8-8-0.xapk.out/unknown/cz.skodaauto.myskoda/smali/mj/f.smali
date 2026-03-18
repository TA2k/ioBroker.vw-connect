.class public final Lmj/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lmj/f;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lmj/f;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lmj/f;->a:Lmj/f;

    .line 7
    .line 8
    return-void
.end method

.method public static a(Lnj/h;)Llj/j;
    .locals 6

    .line 1
    const-string v0, "response"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lnj/h;->a:Lnj/e;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    iget-object v0, p0, Lnj/e;->a:Lnj/d;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v0, 0x0

    .line 14
    :goto_0
    const/4 v1, -0x1

    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    move v0, v1

    .line 18
    goto :goto_1

    .line 19
    :cond_1
    sget-object v2, Lmj/e;->a:[I

    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    aget v0, v2, v0

    .line 26
    .line 27
    :goto_1
    if-eq v0, v1, :cond_4

    .line 28
    .line 29
    const/4 v1, 0x1

    .line 30
    if-eq v0, v1, :cond_3

    .line 31
    .line 32
    const/4 v1, 0x2

    .line 33
    if-ne v0, v1, :cond_2

    .line 34
    .line 35
    new-instance v0, Llj/h;

    .line 36
    .line 37
    iget-object v1, p0, Lnj/e;->b:Ljava/lang/String;

    .line 38
    .line 39
    iget-object v2, p0, Lnj/e;->c:Ljava/lang/String;

    .line 40
    .line 41
    iget-object p0, p0, Lnj/e;->d:Lgz0/p;

    .line 42
    .line 43
    invoke-static {p0}, Lkp/t9;->e(Lgz0/p;)Lmy0/f;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    invoke-static {p0}, Ljp/ab;->c(Lmy0/f;)Ljava/time/Instant;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    invoke-direct {v0, v1, v2, p0}, Llj/h;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/time/Instant;)V

    .line 52
    .line 53
    .line 54
    return-object v0

    .line 55
    :cond_2
    new-instance p0, La8/r0;

    .line 56
    .line 57
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_3
    new-instance v0, Llj/g;

    .line 62
    .line 63
    iget-object v1, p0, Lnj/e;->b:Ljava/lang/String;

    .line 64
    .line 65
    iget-object v2, p0, Lnj/e;->c:Ljava/lang/String;

    .line 66
    .line 67
    iget-object v3, p0, Lnj/e;->d:Lgz0/p;

    .line 68
    .line 69
    invoke-static {v3}, Lkp/t9;->e(Lgz0/p;)Lmy0/f;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    invoke-static {v3}, Ljp/ab;->c(Lmy0/f;)Ljava/time/Instant;

    .line 74
    .line 75
    .line 76
    move-result-object v3

    .line 77
    iget-boolean v4, p0, Lnj/e;->e:Z

    .line 78
    .line 79
    iget-object v5, p0, Lnj/e;->f:Llj/e;

    .line 80
    .line 81
    invoke-direct/range {v0 .. v5}, Llj/g;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/time/Instant;ZLlj/e;)V

    .line 82
    .line 83
    .line 84
    return-object v0

    .line 85
    :cond_4
    sget-object p0, Llj/i;->a:Llj/i;

    .line 86
    .line 87
    return-object p0
.end method
