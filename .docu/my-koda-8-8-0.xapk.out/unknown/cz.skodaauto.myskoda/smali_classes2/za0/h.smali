.class public final synthetic Lza0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Ljava/lang/String;

.field public final synthetic e:Lza0/q;

.field public final synthetic f:Ly6/s;

.field public final synthetic g:F

.field public final synthetic h:F


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lza0/q;Ly6/s;FF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lza0/h;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lza0/h;->e:Lza0/q;

    .line 7
    .line 8
    iput-object p3, p0, Lza0/h;->f:Ly6/s;

    .line 9
    .line 10
    iput p4, p0, Lza0/h;->g:F

    .line 11
    .line 12
    iput p5, p0, Lza0/h;->h:F

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    check-cast p1, Lf7/i;

    .line 2
    .line 3
    check-cast p2, Ll2/o;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const-string p3, "$this$Column"

    .line 11
    .line 12
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sget-object p1, Ly6/o;->a:Ly6/o;

    .line 16
    .line 17
    invoke-static {p1}, Lkp/p7;->c(Ly6/q;)Ly6/q;

    .line 18
    .line 19
    .line 20
    move-result-object p3

    .line 21
    new-instance v0, Lf7/n;

    .line 22
    .line 23
    sget-object v1, Lk7/d;->a:Lk7/d;

    .line 24
    .line 25
    invoke-direct {v0, v1}, Lf7/n;-><init>(Lk7/g;)V

    .line 26
    .line 27
    .line 28
    invoke-interface {p3, v0}, Ly6/q;->d(Ly6/q;)Ly6/q;

    .line 29
    .line 30
    .line 31
    move-result-object p3

    .line 32
    new-instance v0, Li91/b;

    .line 33
    .line 34
    iget-object v1, p0, Lza0/h;->f:Ly6/s;

    .line 35
    .line 36
    iget v2, p0, Lza0/h;->g:F

    .line 37
    .line 38
    iget v3, p0, Lza0/h;->h:F

    .line 39
    .line 40
    iget-object v4, p0, Lza0/h;->e:Lza0/q;

    .line 41
    .line 42
    invoke-direct {v0, v1, v2, v3, v4}, Li91/b;-><init>(Ly6/s;FFLza0/q;)V

    .line 43
    .line 44
    .line 45
    const v1, 0x3bc71f33

    .line 46
    .line 47
    .line 48
    invoke-static {v1, p2, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    const/16 v1, 0x180

    .line 53
    .line 54
    sget-object v2, Lf7/c;->d:Lf7/c;

    .line 55
    .line 56
    invoke-static {p3, v2, v0, p2, v1}, Lkp/j7;->a(Ly6/q;Lf7/c;Lt2/b;Ll2/o;I)V

    .line 57
    .line 58
    .line 59
    iget-object v5, p0, Lza0/h;->d:Ljava/lang/String;

    .line 60
    .line 61
    const/4 p0, 0x0

    .line 62
    if-eqz v5, :cond_0

    .line 63
    .line 64
    move-object v9, p2

    .line 65
    check-cast v9, Ll2/t;

    .line 66
    .line 67
    const p2, 0x65d23b3a

    .line 68
    .line 69
    .line 70
    invoke-virtual {v9, p2}, Ll2/t;->Y(I)V

    .line 71
    .line 72
    .line 73
    iget-object v7, v4, Lza0/q;->f:Lj7/g;

    .line 74
    .line 75
    invoke-static {p1}, Lkp/p7;->f(Ly6/q;)Ly6/q;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    invoke-static {p1}, Lkp/p7;->e(Ly6/q;)Ly6/q;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    const/4 p2, 0x4

    .line 84
    int-to-float p2, p2

    .line 85
    const/16 p3, 0xe

    .line 86
    .line 87
    const/4 v0, 0x0

    .line 88
    invoke-static {p1, p2, v0, v0, p3}, Lkp/n7;->c(Ly6/q;FFFI)Ly6/q;

    .line 89
    .line 90
    .line 91
    move-result-object v6

    .line 92
    const/16 v10, 0xc00

    .line 93
    .line 94
    const/4 v11, 0x0

    .line 95
    const/4 v8, 0x1

    .line 96
    invoke-static/range {v5 .. v11}, Llp/mb;->a(Ljava/lang/String;Ly6/q;Lj7/g;ILl2/o;II)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v9, p0}, Ll2/t;->q(Z)V

    .line 100
    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_0
    check-cast p2, Ll2/t;

    .line 104
    .line 105
    const p1, 0x650f78b1

    .line 106
    .line 107
    .line 108
    invoke-virtual {p2, p1}, Ll2/t;->Y(I)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {p2, p0}, Ll2/t;->q(Z)V

    .line 112
    .line 113
    .line 114
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 115
    .line 116
    return-object p0
.end method
