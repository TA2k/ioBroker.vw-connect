.class public final synthetic Le71/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/q;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:Z

.field public final synthetic f:Lh71/x;

.field public final synthetic g:Ljava/lang/Float;

.field public final synthetic h:Le71/g;


# direct methods
.method public synthetic constructor <init>(FZLh71/x;Ljava/lang/Float;Le71/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Le71/m;->d:F

    .line 5
    .line 6
    iput-boolean p2, p0, Le71/m;->e:Z

    .line 7
    .line 8
    iput-object p3, p0, Le71/m;->f:Lh71/x;

    .line 9
    .line 10
    iput-object p4, p0, Le71/m;->g:Ljava/lang/Float;

    .line 11
    .line 12
    iput-object p5, p0, Le71/m;->h:Le71/g;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p1, Ljava/lang/Boolean;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    check-cast p2, Ljava/lang/Boolean;

    .line 7
    .line 8
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    check-cast p3, Lx2/s;

    .line 12
    .line 13
    check-cast p4, Ll2/o;

    .line 14
    .line 15
    check-cast p5, Ljava/lang/Integer;

    .line 16
    .line 17
    invoke-virtual {p5}, Ljava/lang/Integer;->intValue()I

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    const-string p2, "clickableModifier"

    .line 22
    .line 23
    invoke-static {p3, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    and-int/lit16 p2, p1, 0x180

    .line 27
    .line 28
    if-nez p2, :cond_1

    .line 29
    .line 30
    move-object p2, p4

    .line 31
    check-cast p2, Ll2/t;

    .line 32
    .line 33
    invoke-virtual {p2, p3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result p2

    .line 37
    if-eqz p2, :cond_0

    .line 38
    .line 39
    const/16 p2, 0x100

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const/16 p2, 0x80

    .line 43
    .line 44
    :goto_0
    or-int/2addr p1, p2

    .line 45
    :cond_1
    and-int/lit16 p2, p1, 0x481

    .line 46
    .line 47
    const/16 p5, 0x480

    .line 48
    .line 49
    const/4 v0, 0x1

    .line 50
    if-eq p2, p5, :cond_2

    .line 51
    .line 52
    move p2, v0

    .line 53
    goto :goto_1

    .line 54
    :cond_2
    const/4 p2, 0x0

    .line 55
    :goto_1
    and-int/2addr p1, v0

    .line 56
    move-object v4, p4

    .line 57
    check-cast v4, Ll2/t;

    .line 58
    .line 59
    invoke-virtual {v4, p1, p2}, Ll2/t;->O(IZ)Z

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    if-eqz p1, :cond_3

    .line 64
    .line 65
    const/16 p1, 0x58

    .line 66
    .line 67
    int-to-float p1, p1

    .line 68
    invoke-static {p3, p1, p1}, Landroidx/compose/foundation/layout/d;->a(Lx2/s;FF)Lx2/s;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    move-object p1, p0

    .line 73
    new-instance p0, Le71/o;

    .line 74
    .line 75
    move-object p2, p1

    .line 76
    iget p1, p2, Le71/m;->d:F

    .line 77
    .line 78
    move-object p3, p2

    .line 79
    iget-boolean p2, p3, Le71/m;->e:Z

    .line 80
    .line 81
    move-object p4, p3

    .line 82
    iget-object p3, p4, Le71/m;->f:Lh71/x;

    .line 83
    .line 84
    move-object p5, p4

    .line 85
    iget-object p4, p5, Le71/m;->g:Ljava/lang/Float;

    .line 86
    .line 87
    iget-object p5, p5, Le71/m;->h:Le71/g;

    .line 88
    .line 89
    invoke-direct/range {p0 .. p5}, Le71/o;-><init>(FZLh71/x;Ljava/lang/Float;Le71/g;)V

    .line 90
    .line 91
    .line 92
    const p1, 0x63cdc217

    .line 93
    .line 94
    .line 95
    invoke-static {p1, v4, p0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    const/16 v5, 0xc00

    .line 100
    .line 101
    const/4 v6, 0x6

    .line 102
    const/4 v1, 0x0

    .line 103
    const/4 v2, 0x0

    .line 104
    invoke-static/range {v0 .. v6}, Lk1/d;->a(Lx2/s;Lx2/e;ZLt2/b;Ll2/o;II)V

    .line 105
    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_3
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 109
    .line 110
    .line 111
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 112
    .line 113
    return-object p0
.end method
