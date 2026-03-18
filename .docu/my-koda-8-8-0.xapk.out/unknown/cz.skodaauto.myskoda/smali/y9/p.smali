.class public final synthetic Ly9/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnClickListener;


# instance fields
.field public final synthetic d:Ly9/f;

.field public final synthetic e:Lt7/l0;

.field public final synthetic f:Lt7/q0;

.field public final synthetic g:Ly9/o;


# direct methods
.method public synthetic constructor <init>(Ly9/f;Lt7/l0;Lt7/q0;Ly9/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ly9/p;->d:Ly9/f;

    .line 5
    .line 6
    iput-object p2, p0, Ly9/p;->e:Lt7/l0;

    .line 7
    .line 8
    iput-object p3, p0, Ly9/p;->f:Lt7/q0;

    .line 9
    .line 10
    iput-object p4, p0, Ly9/p;->g:Ly9/o;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final onClick(Landroid/view/View;)V
    .locals 5

    .line 1
    iget-object p1, p0, Ly9/p;->e:Lt7/l0;

    .line 2
    .line 3
    check-cast p1, Lap0/o;

    .line 4
    .line 5
    const/16 v0, 0x1d

    .line 6
    .line 7
    invoke-virtual {p1, v0}, Lap0/o;->I(I)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    check-cast p1, La8/i0;

    .line 15
    .line 16
    invoke-virtual {p1}, La8/i0;->q0()Lt7/u0;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Lj8/i;

    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    new-instance v1, Lj8/h;

    .line 26
    .line 27
    invoke-direct {v1, v0}, Lj8/h;-><init>(Lj8/i;)V

    .line 28
    .line 29
    .line 30
    new-instance v0, Lt7/r0;

    .line 31
    .line 32
    iget-object v2, p0, Ly9/p;->g:Ly9/o;

    .line 33
    .line 34
    iget v3, v2, Ly9/o;->b:I

    .line 35
    .line 36
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    invoke-static {v3}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    iget-object v4, p0, Ly9/p;->f:Lt7/q0;

    .line 45
    .line 46
    invoke-direct {v0, v4, v3}, Lt7/r0;-><init>(Lt7/q0;Ljava/util/List;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v1, v0}, Lj8/h;->e(Lt7/r0;)Lt7/t0;

    .line 50
    .line 51
    .line 52
    iget-object v0, v2, Ly9/o;->a:Lt7/v0;

    .line 53
    .line 54
    iget-object v0, v0, Lt7/v0;->b:Lt7/q0;

    .line 55
    .line 56
    iget v0, v0, Lt7/q0;->c:I

    .line 57
    .line 58
    const/4 v3, 0x0

    .line 59
    invoke-virtual {v1, v0, v3}, Lt7/t0;->i(IZ)Lt7/t0;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v1}, Lt7/t0;->a()Lt7/u0;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    invoke-virtual {p1, v0}, La8/i0;->D0(Lt7/u0;)V

    .line 67
    .line 68
    .line 69
    iget-object p1, v2, Ly9/o;->c:Ljava/lang/String;

    .line 70
    .line 71
    iget-object p0, p0, Ly9/p;->d:Ly9/f;

    .line 72
    .line 73
    iget v0, p0, Ly9/f;->f:I

    .line 74
    .line 75
    packed-switch v0, :pswitch_data_0

    .line 76
    .line 77
    .line 78
    goto :goto_0

    .line 79
    :pswitch_0
    iget-object v0, p0, Ly9/f;->g:Ly9/r;

    .line 80
    .line 81
    iget-object v0, v0, Ly9/r;->o:Ly9/m;

    .line 82
    .line 83
    const/4 v1, 0x1

    .line 84
    iget-object v0, v0, Ly9/m;->e:[Ljava/lang/String;

    .line 85
    .line 86
    aput-object p1, v0, v1

    .line 87
    .line 88
    :goto_0
    iget-object p0, p0, Ly9/f;->e:Ly9/r;

    .line 89
    .line 90
    iget-object p0, p0, Ly9/r;->t:Landroid/widget/PopupWindow;

    .line 91
    .line 92
    invoke-virtual {p0}, Landroid/widget/PopupWindow;->dismiss()V

    .line 93
    .line 94
    .line 95
    return-void

    .line 96
    nop

    .line 97
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
