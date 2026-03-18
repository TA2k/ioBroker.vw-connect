.class public final Lh2/p5;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lh2/n5;

.field public final synthetic e:Z

.field public final synthetic f:Lt2/b;


# direct methods
.method public constructor <init>(Lh2/n5;ZLt2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/p5;->d:Lh2/n5;

    .line 5
    .line 6
    iput-boolean p2, p0, Lh2/p5;->e:Z

    .line 7
    .line 8
    iput-object p3, p0, Lh2/p5;->f:Lt2/b;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Ll2/o;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Number;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    and-int/lit8 v0, p2, 0x3

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    const/4 v2, 0x0

    .line 13
    const/4 v3, 0x1

    .line 14
    if-eq v0, v1, :cond_0

    .line 15
    .line 16
    move v0, v3

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v0, v2

    .line 19
    :goto_0
    and-int/2addr p2, v3

    .line 20
    check-cast p1, Ll2/t;

    .line 21
    .line 22
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 23
    .line 24
    .line 25
    move-result p2

    .line 26
    if-eqz p2, :cond_2

    .line 27
    .line 28
    const p2, -0x33841157    # -6.6042532E7f

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p1, v2}, Ll2/t;->q(Z)V

    .line 35
    .line 36
    .line 37
    sget-object p2, Lh2/p1;->a:Ll2/e0;

    .line 38
    .line 39
    iget-boolean v0, p0, Lh2/p5;->e:Z

    .line 40
    .line 41
    iget-object v1, p0, Lh2/p5;->d:Lh2/n5;

    .line 42
    .line 43
    if-eqz v0, :cond_1

    .line 44
    .line 45
    iget-wide v0, v1, Lh2/n5;->a:J

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    iget-wide v0, v1, Lh2/n5;->d:J

    .line 49
    .line 50
    :goto_1
    invoke-static {v0, v1, p2}, Lf2/m0;->s(JLl2/e0;)Ll2/t1;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    new-instance v0, Lf2/c0;

    .line 55
    .line 56
    iget-object p0, p0, Lh2/p5;->f:Lt2/b;

    .line 57
    .line 58
    const/16 v1, 0x8

    .line 59
    .line 60
    invoke-direct {v0, p0, v1}, Lf2/c0;-><init>(Lt2/b;I)V

    .line 61
    .line 62
    .line 63
    const p0, -0x3542ef07    # -6195324.5f

    .line 64
    .line 65
    .line 66
    invoke-static {p0, p1, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    const/16 v0, 0x38

    .line 71
    .line 72
    invoke-static {p2, p0, p1, v0}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 73
    .line 74
    .line 75
    const p0, -0x33716f37    # -7.4745416E7f

    .line 76
    .line 77
    .line 78
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p1, v2}, Ll2/t;->q(Z)V

    .line 82
    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 86
    .line 87
    .line 88
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 89
    .line 90
    return-object p0
.end method
