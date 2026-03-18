.class public abstract Lgz0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lqz0/g;
    with = Lmz0/c;
.end annotation


# static fields
.field public static final Companion:Lgz0/b;

.field public static final a:Lgz0/f;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lgz0/b;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lgz0/k;->Companion:Lgz0/b;

    .line 7
    .line 8
    new-instance v0, Lgz0/j;

    .line 9
    .line 10
    const-wide/16 v1, 0x1

    .line 11
    .line 12
    invoke-direct {v0, v1, v2}, Lgz0/j;-><init>(J)V

    .line 13
    .line 14
    .line 15
    const/16 v1, 0x3e8

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Lgz0/j;->b(I)Lgz0/j;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-virtual {v0, v1}, Lgz0/j;->b(I)Lgz0/j;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-virtual {v0, v1}, Lgz0/j;->b(I)Lgz0/j;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    const/16 v1, 0x3c

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Lgz0/j;->b(I)Lgz0/j;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {v0, v1}, Lgz0/j;->b(I)Lgz0/j;

    .line 36
    .line 37
    .line 38
    new-instance v0, Lgz0/f;

    .line 39
    .line 40
    const/4 v1, 0x1

    .line 41
    invoke-direct {v0, v1}, Lgz0/f;-><init>(I)V

    .line 42
    .line 43
    .line 44
    sput-object v0, Lgz0/k;->a:Lgz0/f;

    .line 45
    .line 46
    new-instance v0, Lgz0/f;

    .line 47
    .line 48
    const/4 v2, 0x7

    .line 49
    invoke-static {v1, v2}, Ljava/lang/Math;->multiplyExact(II)I

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    invoke-direct {v0, v2}, Lgz0/f;-><init>(I)V

    .line 54
    .line 55
    .line 56
    new-instance v0, Lgz0/h;

    .line 57
    .line 58
    invoke-direct {v0, v1}, Lgz0/h;-><init>(I)V

    .line 59
    .line 60
    .line 61
    new-instance v0, Lgz0/h;

    .line 62
    .line 63
    const/4 v2, 0x3

    .line 64
    invoke-static {v1, v2}, Ljava/lang/Math;->multiplyExact(II)I

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    invoke-direct {v0, v2}, Lgz0/h;-><init>(I)V

    .line 69
    .line 70
    .line 71
    new-instance v0, Lgz0/h;

    .line 72
    .line 73
    const/16 v2, 0xc

    .line 74
    .line 75
    invoke-static {v1, v2}, Ljava/lang/Math;->multiplyExact(II)I

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    invoke-direct {v0, v1}, Lgz0/h;-><init>(I)V

    .line 80
    .line 81
    .line 82
    new-instance v0, Lgz0/h;

    .line 83
    .line 84
    const/16 v2, 0x64

    .line 85
    .line 86
    invoke-static {v1, v2}, Ljava/lang/Math;->multiplyExact(II)I

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    invoke-direct {v0, v1}, Lgz0/h;-><init>(I)V

    .line 91
    .line 92
    .line 93
    return-void
.end method

.method public static a(ILjava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, v0, :cond_0

    .line 3
    .line 4
    return-object p1

    .line 5
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const/16 p0, 0x2d

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method
