.class public final synthetic Lt10/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ls10/x;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Ls10/x;Lay0/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Lt10/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lt10/h;->e:Ls10/x;

    .line 4
    .line 5
    iput-object p2, p0, Lt10/h;->f:Lay0/a;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lt10/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lk1/q;

    .line 7
    .line 8
    check-cast p2, Ll2/o;

    .line 9
    .line 10
    check-cast p3, Ljava/lang/Integer;

    .line 11
    .line 12
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 13
    .line 14
    .line 15
    move-result p3

    .line 16
    const-string v0, "$this$GradientBox"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    and-int/lit8 p1, p3, 0x11

    .line 22
    .line 23
    const/16 v0, 0x10

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    if-eq p1, v0, :cond_0

    .line 27
    .line 28
    move p1, v1

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 p1, 0x0

    .line 31
    :goto_0
    and-int/2addr p3, v1

    .line 32
    move-object v5, p2

    .line 33
    check-cast v5, Ll2/t;

    .line 34
    .line 35
    invoke-virtual {v5, p3, p1}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-eqz p1, :cond_1

    .line 40
    .line 41
    const p1, 0x7f120f3d

    .line 42
    .line 43
    .line 44
    invoke-static {v5, p1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v4

    .line 48
    iget-object p1, p0, Lt10/h;->e:Ls10/x;

    .line 49
    .line 50
    iget-boolean v7, p1, Ls10/x;->f:Z

    .line 51
    .line 52
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 53
    .line 54
    const-string p2, "departure_timer_button_save"

    .line 55
    .line 56
    invoke-static {p1, p2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 57
    .line 58
    .line 59
    move-result-object v6

    .line 60
    const/16 v0, 0x180

    .line 61
    .line 62
    const/16 v1, 0x28

    .line 63
    .line 64
    iget-object v2, p0, Lt10/h;->f:Lay0/a;

    .line 65
    .line 66
    const/4 v3, 0x0

    .line 67
    const/4 v8, 0x0

    .line 68
    invoke-static/range {v0 .. v8}, Li91/j0;->X(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 69
    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_1
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 73
    .line 74
    .line 75
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    return-object p0

    .line 78
    :pswitch_0
    check-cast p1, Lb1/a0;

    .line 79
    .line 80
    check-cast p2, Ll2/o;

    .line 81
    .line 82
    check-cast p3, Ljava/lang/Integer;

    .line 83
    .line 84
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 85
    .line 86
    .line 87
    const-string p3, "$this$AnimatedVisibility"

    .line 88
    .line 89
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    const/4 p1, 0x0

    .line 93
    iget-object p3, p0, Lt10/h;->e:Ls10/x;

    .line 94
    .line 95
    iget-object p0, p0, Lt10/h;->f:Lay0/a;

    .line 96
    .line 97
    invoke-static {p3, p0, p2, p1}, Lt10/a;->m(Ls10/x;Lay0/a;Ll2/o;I)V

    .line 98
    .line 99
    .line 100
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 101
    .line 102
    return-object p0

    .line 103
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
