.class public final synthetic Lxf0/u1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/v;


# instance fields
.field public final synthetic d:Ll2/b1;

.field public final synthetic e:Ll2/b1;

.field public final synthetic f:Ll2/b1;

.field public final synthetic g:Ll2/b1;

.field public final synthetic h:Ll2/b1;

.field public final synthetic i:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/u1;->d:Ll2/b1;

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/u1;->e:Ll2/b1;

    .line 7
    .line 8
    iput-object p3, p0, Lxf0/u1;->f:Ll2/b1;

    .line 9
    .line 10
    iput-object p4, p0, Lxf0/u1;->g:Ll2/b1;

    .line 11
    .line 12
    iput-object p5, p0, Lxf0/u1;->h:Ll2/b1;

    .line 13
    .line 14
    iput-object p6, p0, Lxf0/u1;->i:Ll2/b1;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final f(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V
    .locals 0

    .line 1
    sget-object p1, Lxf0/v1;->a:[I

    .line 2
    .line 3
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    aget p1, p1, p2

    .line 8
    .line 9
    packed-switch p1, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    goto :goto_0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lxf0/u1;->i:Ll2/b1;

    .line 14
    .line 15
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Lay0/a;

    .line 20
    .line 21
    if-eqz p0, :cond_0

    .line 22
    .line 23
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :pswitch_1
    iget-object p0, p0, Lxf0/u1;->h:Ll2/b1;

    .line 28
    .line 29
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    check-cast p0, Lay0/a;

    .line 34
    .line 35
    if-eqz p0, :cond_0

    .line 36
    .line 37
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :pswitch_2
    iget-object p0, p0, Lxf0/u1;->g:Ll2/b1;

    .line 42
    .line 43
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    check-cast p0, Lay0/a;

    .line 48
    .line 49
    if-eqz p0, :cond_0

    .line 50
    .line 51
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :pswitch_3
    iget-object p0, p0, Lxf0/u1;->f:Ll2/b1;

    .line 56
    .line 57
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    check-cast p0, Lay0/a;

    .line 62
    .line 63
    if-eqz p0, :cond_0

    .line 64
    .line 65
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    return-void

    .line 69
    :pswitch_4
    iget-object p0, p0, Lxf0/u1;->e:Ll2/b1;

    .line 70
    .line 71
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    check-cast p0, Lay0/a;

    .line 76
    .line 77
    if-eqz p0, :cond_0

    .line 78
    .line 79
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    return-void

    .line 83
    :pswitch_5
    iget-object p0, p0, Lxf0/u1;->d:Ll2/b1;

    .line 84
    .line 85
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    check-cast p0, Lay0/a;

    .line 90
    .line 91
    if-eqz p0, :cond_0

    .line 92
    .line 93
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    :cond_0
    :goto_0
    return-void

    .line 97
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
