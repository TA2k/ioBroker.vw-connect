.class public final synthetic Lxf0/k3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lxf0/j3;

.field public final synthetic e:J

.field public final synthetic f:Ll2/t2;


# direct methods
.method public synthetic constructor <init>(Lxf0/j3;JLl2/t2;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/k3;->d:Lxf0/j3;

    .line 5
    .line 6
    iput-wide p2, p0, Lxf0/k3;->e:J

    .line 7
    .line 8
    iput-object p4, p0, Lxf0/k3;->f:Ll2/t2;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Lg3/d;

    .line 3
    .line 4
    const-string p1, "$this$drawBehind"

    .line 5
    .line 6
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iget-object p1, p0, Lxf0/k3;->d:Lxf0/j3;

    .line 10
    .line 11
    iget-boolean v2, p1, Lxf0/j3;->d:Z

    .line 12
    .line 13
    iget-wide v3, p1, Lxf0/j3;->c:J

    .line 14
    .line 15
    move-wide v4, v3

    .line 16
    new-instance v3, Le3/s;

    .line 17
    .line 18
    invoke-direct {v3, v4, v5}, Le3/s;-><init>(J)V

    .line 19
    .line 20
    .line 21
    iget-object p1, p0, Lxf0/k3;->f:Ll2/t2;

    .line 22
    .line 23
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    check-cast p1, Ljava/lang/Number;

    .line 28
    .line 29
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 30
    .line 31
    .line 32
    move-result v6

    .line 33
    sget p1, Lxf0/m3;->a:F

    .line 34
    .line 35
    invoke-interface {v0, p1}, Lt4/c;->w0(F)F

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    invoke-interface {v0}, Lg3/d;->e()J

    .line 40
    .line 41
    .line 42
    move-result-wide v7

    .line 43
    invoke-static {v7, v8}, Ld3/e;->c(J)F

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    const/high16 v1, 0x40000000    # 2.0f

    .line 48
    .line 49
    div-float/2addr p1, v1

    .line 50
    const/4 v1, 0x2

    .line 51
    int-to-float v1, v1

    .line 52
    div-float v1, v4, v1

    .line 53
    .line 54
    sub-float v5, p1, v1

    .line 55
    .line 56
    new-instance v7, Lg3/h;

    .line 57
    .line 58
    const/4 v12, 0x0

    .line 59
    const/16 v13, 0x1e

    .line 60
    .line 61
    const/4 v9, 0x0

    .line 62
    const/4 v10, 0x0

    .line 63
    const/4 v11, 0x0

    .line 64
    move v8, v4

    .line 65
    invoke-direct/range {v7 .. v13}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 66
    .line 67
    .line 68
    new-instance v1, Lxf0/l3;

    .line 69
    .line 70
    invoke-direct/range {v1 .. v6}, Lxf0/l3;-><init>(ZLe3/s;FFF)V

    .line 71
    .line 72
    .line 73
    move-object p1, v1

    .line 74
    move v3, v5

    .line 75
    const-wide/16 v4, 0x0

    .line 76
    .line 77
    move-object v6, v7

    .line 78
    const/16 v7, 0x6c

    .line 79
    .line 80
    iget-wide v1, p0, Lxf0/k3;->e:J

    .line 81
    .line 82
    invoke-static/range {v0 .. v7}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {p1, v0}, Lxf0/l3;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 89
    .line 90
    return-object p0
.end method
