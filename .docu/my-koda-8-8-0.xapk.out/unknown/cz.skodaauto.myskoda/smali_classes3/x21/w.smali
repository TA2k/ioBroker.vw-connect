.class public final Lx21/w;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# static fields
.field public static final g:Lx21/w;

.field public static final h:Lx21/w;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lx21/w;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Lx21/w;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lx21/w;->g:Lx21/w;

    .line 9
    .line 10
    new-instance v0, Lx21/w;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Lx21/w;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lx21/w;->h:Lx21/w;

    .line 17
    .line 18
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lx21/w;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lx21/w;->f:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ld3/c;

    .line 7
    .line 8
    check-cast p2, Ld3/c;

    .line 9
    .line 10
    const-string p0, "draggingItem"

    .line 11
    .line 12
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string p0, "item"

    .line 16
    .line 17
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    iget p0, p1, Ld3/c;->a:F

    .line 21
    .line 22
    iget p1, p1, Ld3/c;->c:F

    .line 23
    .line 24
    invoke-virtual {p2}, Ld3/c;->b()J

    .line 25
    .line 26
    .line 27
    move-result-wide v0

    .line 28
    invoke-static {v0, v1}, Ld3/b;->e(J)F

    .line 29
    .line 30
    .line 31
    move-result p2

    .line 32
    cmpl-float p0, p2, p0

    .line 33
    .line 34
    if-ltz p0, :cond_0

    .line 35
    .line 36
    cmpg-float p0, p2, p1

    .line 37
    .line 38
    if-gez p0, :cond_0

    .line 39
    .line 40
    const/4 p0, 0x1

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const/4 p0, 0x0

    .line 43
    :goto_0
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :pswitch_0
    check-cast p1, Ld3/c;

    .line 49
    .line 50
    check-cast p2, Ld3/c;

    .line 51
    .line 52
    const-string p0, "draggingItem"

    .line 53
    .line 54
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    const-string p0, "item"

    .line 58
    .line 59
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    iget p0, p1, Ld3/c;->b:F

    .line 63
    .line 64
    iget p1, p1, Ld3/c;->d:F

    .line 65
    .line 66
    invoke-virtual {p2}, Ld3/c;->b()J

    .line 67
    .line 68
    .line 69
    move-result-wide v0

    .line 70
    invoke-static {v0, v1}, Ld3/b;->f(J)F

    .line 71
    .line 72
    .line 73
    move-result p2

    .line 74
    cmpl-float p0, p2, p0

    .line 75
    .line 76
    if-ltz p0, :cond_1

    .line 77
    .line 78
    cmpg-float p0, p2, p1

    .line 79
    .line 80
    if-gez p0, :cond_1

    .line 81
    .line 82
    const/4 p0, 0x1

    .line 83
    goto :goto_1

    .line 84
    :cond_1
    const/4 p0, 0x0

    .line 85
    :goto_1
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    return-object p0

    .line 90
    nop

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
