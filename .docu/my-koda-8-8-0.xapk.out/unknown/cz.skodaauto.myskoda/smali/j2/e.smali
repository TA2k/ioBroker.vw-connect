.class public final synthetic Lj2/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lj2/p;

.field public final synthetic e:Z

.field public final synthetic f:F

.field public final synthetic g:F

.field public final synthetic h:Le3/n0;


# direct methods
.method public synthetic constructor <init>(Lj2/p;ZFFLe3/n0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lj2/e;->d:Lj2/p;

    .line 5
    .line 6
    iput-boolean p2, p0, Lj2/e;->e:Z

    .line 7
    .line 8
    iput p3, p0, Lj2/e;->f:F

    .line 9
    .line 10
    iput p4, p0, Lj2/e;->g:F

    .line 11
    .line 12
    iput-object p5, p0, Lj2/e;->h:Le3/n0;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    check-cast p1, Le3/k0;

    .line 2
    .line 3
    iget-object v0, p0, Lj2/e;->d:Lj2/p;

    .line 4
    .line 5
    iget-object v1, v0, Lj2/p;->a:Lc1/c;

    .line 6
    .line 7
    invoke-virtual {v1}, Lc1/c;->d()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    check-cast v1, Ljava/lang/Number;

    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    const/4 v2, 0x0

    .line 18
    cmpl-float v1, v1, v2

    .line 19
    .line 20
    const/4 v3, 0x1

    .line 21
    if-gtz v1, :cond_1

    .line 22
    .line 23
    iget-boolean v1, p0, Lj2/e;->e:Z

    .line 24
    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v1, 0x0

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    :goto_0
    move v1, v3

    .line 31
    :goto_1
    iget-object v0, v0, Lj2/p;->a:Lc1/c;

    .line 32
    .line 33
    invoke-virtual {v0}, Lc1/c;->d()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Ljava/lang/Number;

    .line 38
    .line 39
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    iget v4, p0, Lj2/e;->f:F

    .line 44
    .line 45
    invoke-interface {p1, v4}, Lt4/c;->Q(F)I

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    int-to-float v4, v4

    .line 50
    mul-float/2addr v0, v4

    .line 51
    iget-wide v4, p1, Le3/k0;->t:J

    .line 52
    .line 53
    const-wide v6, 0xffffffffL

    .line 54
    .line 55
    .line 56
    .line 57
    .line 58
    and-long/2addr v4, v6

    .line 59
    long-to-int v4, v4

    .line 60
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    sub-float/2addr v0, v4

    .line 65
    invoke-virtual {p1, v0}, Le3/k0;->D(F)V

    .line 66
    .line 67
    .line 68
    if-eqz v1, :cond_2

    .line 69
    .line 70
    iget-object v0, p1, Le3/k0;->u:Lt4/c;

    .line 71
    .line 72
    invoke-interface {v0}, Lt4/c;->a()F

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    iget v1, p0, Lj2/e;->g:F

    .line 77
    .line 78
    mul-float v2, v0, v1

    .line 79
    .line 80
    :cond_2
    invoke-virtual {p1, v2}, Le3/k0;->t(F)V

    .line 81
    .line 82
    .line 83
    iget-object p0, p0, Lj2/e;->h:Le3/n0;

    .line 84
    .line 85
    invoke-virtual {p1, p0}, Le3/k0;->w(Le3/n0;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p1, v3}, Le3/k0;->d(Z)V

    .line 89
    .line 90
    .line 91
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    return-object p0
.end method
