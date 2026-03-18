.class public final Ljz0/u;
.super Ljz0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljz0/r;

.field public final b:I

.field public final c:I

.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/Integer;

.field public final f:Lhz0/d1;

.field public final g:I


# direct methods
.method public constructor <init>(Ljz0/r;IILhz0/d1;I)V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    iget-object v1, p1, Ljz0/r;->e:Ljava/lang/String;

    .line 7
    .line 8
    and-int/lit8 v2, p5, 0x10

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    move-object v0, v3

    .line 14
    :cond_0
    and-int/lit8 p5, p5, 0x20

    .line 15
    .line 16
    if-eqz p5, :cond_1

    .line 17
    .line 18
    move-object p4, v3

    .line 19
    :cond_1
    const-string p5, "name"

    .line 20
    .line 21
    invoke-static {v1, p5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 25
    .line 26
    .line 27
    iput-object p1, p0, Ljz0/u;->a:Ljz0/r;

    .line 28
    .line 29
    iput p2, p0, Ljz0/u;->b:I

    .line 30
    .line 31
    iput p3, p0, Ljz0/u;->c:I

    .line 32
    .line 33
    iput-object v1, p0, Ljz0/u;->d:Ljava/lang/String;

    .line 34
    .line 35
    iput-object v0, p0, Ljz0/u;->e:Ljava/lang/Integer;

    .line 36
    .line 37
    iput-object p4, p0, Ljz0/u;->f:Lhz0/d1;

    .line 38
    .line 39
    const/16 p1, 0xa

    .line 40
    .line 41
    if-ge p3, p1, :cond_2

    .line 42
    .line 43
    const/4 p1, 0x1

    .line 44
    goto :goto_0

    .line 45
    :cond_2
    const/16 p1, 0x64

    .line 46
    .line 47
    if-ge p3, p1, :cond_3

    .line 48
    .line 49
    const/4 p1, 0x2

    .line 50
    goto :goto_0

    .line 51
    :cond_3
    const/16 p1, 0x3e8

    .line 52
    .line 53
    if-ge p3, p1, :cond_4

    .line 54
    .line 55
    const/4 p1, 0x3

    .line 56
    :goto_0
    iput p1, p0, Ljz0/u;->g:I

    .line 57
    .line 58
    return-void

    .line 59
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 60
    .line 61
    const-string p1, "Max value "

    .line 62
    .line 63
    const-string p2, " is too large"

    .line 64
    .line 65
    invoke-static {p1, p3, p2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw p0
.end method


# virtual methods
.method public final a()Ljz0/r;
    .locals 0

    .line 1
    iget-object p0, p0, Ljz0/u;->a:Ljz0/r;

    .line 2
    .line 3
    return-object p0
.end method

.method public final b()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Ljz0/u;->e:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final c()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ljz0/u;->d:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d()Lhz0/d1;
    .locals 0

    .line 1
    iget-object p0, p0, Ljz0/u;->f:Lhz0/d1;

    .line 2
    .line 3
    return-object p0
.end method
