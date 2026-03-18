.class public final Lnn/m;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p6, p0, Lnn/m;->f:I

    iput-object p1, p0, Lnn/m;->g:Ljava/lang/Object;

    iput-object p2, p0, Lnn/m;->h:Ljava/lang/Object;

    iput-object p3, p0, Lnn/m;->i:Ljava/lang/Object;

    iput-object p4, p0, Lnn/m;->j:Ljava/lang/Object;

    iput-object p5, p0, Lnn/m;->k:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Lvy0/b0;Lay0/k;Lx21/k;Ll2/b1;Ll2/b1;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lnn/m;->f:I

    .line 2
    iput-object p1, p0, Lnn/m;->h:Ljava/lang/Object;

    iput-object p2, p0, Lnn/m;->g:Ljava/lang/Object;

    iput-object p3, p0, Lnn/m;->i:Ljava/lang/Object;

    iput-object p4, p0, Lnn/m;->j:Ljava/lang/Object;

    iput-object p5, p0, Lnn/m;->k:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lnn/m;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 7
    .line 8
    iget-object p1, p0, Lnn/m;->g:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p1, Lx4/t;

    .line 11
    .line 12
    iget-object v0, p1, Lx4/t;->q:Landroid/view/WindowManager;

    .line 13
    .line 14
    iget-object v1, p1, Lx4/t;->r:Landroid/view/WindowManager$LayoutParams;

    .line 15
    .line 16
    invoke-interface {v0, p1, v1}, Landroid/view/ViewManager;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    .line 17
    .line 18
    .line 19
    iget-object v0, p0, Lnn/m;->h:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Lay0/a;

    .line 22
    .line 23
    iget-object v1, p0, Lnn/m;->i:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v1, Lx4/w;

    .line 26
    .line 27
    iget-object v2, p0, Lnn/m;->j:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v2, Ljava/lang/String;

    .line 30
    .line 31
    iget-object p0, p0, Lnn/m;->k:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Lt4/m;

    .line 34
    .line 35
    invoke-virtual {p1, v0, v1, v2, p0}, Lx4/t;->k(Lay0/a;Lx4/w;Ljava/lang/String;Lt4/m;)V

    .line 36
    .line 37
    .line 38
    new-instance p0, La2/j;

    .line 39
    .line 40
    const/16 v0, 0x13

    .line 41
    .line 42
    invoke-direct {p0, p1, v0}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 43
    .line 44
    .line 45
    return-object p0

    .line 46
    :pswitch_0
    check-cast p1, Ld3/b;

    .line 47
    .line 48
    iget-wide v0, p1, Ld3/b;->a:J

    .line 49
    .line 50
    iget-object p1, p0, Lnn/m;->h:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast p1, Lvy0/b0;

    .line 53
    .line 54
    new-instance v2, Lws/b;

    .line 55
    .line 56
    iget-object v3, p0, Lnn/m;->i:Ljava/lang/Object;

    .line 57
    .line 58
    move-object v4, v3

    .line 59
    check-cast v4, Lx21/k;

    .line 60
    .line 61
    iget-object v3, p0, Lnn/m;->j:Ljava/lang/Object;

    .line 62
    .line 63
    move-object v5, v3

    .line 64
    check-cast v5, Ll2/b1;

    .line 65
    .line 66
    iget-object v3, p0, Lnn/m;->k:Ljava/lang/Object;

    .line 67
    .line 68
    move-object v6, v3

    .line 69
    check-cast v6, Ll2/b1;

    .line 70
    .line 71
    const/4 v3, 0x2

    .line 72
    const/4 v7, 0x0

    .line 73
    invoke-direct/range {v2 .. v7}, Lws/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 74
    .line 75
    .line 76
    const/4 v3, 0x3

    .line 77
    invoke-static {p1, v7, v7, v2, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 78
    .line 79
    .line 80
    iget-object p0, p0, Lnn/m;->g:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast p0, Lay0/k;

    .line 83
    .line 84
    new-instance p1, Ld3/b;

    .line 85
    .line 86
    invoke-direct {p1, v0, v1}, Ld3/b;-><init>(J)V

    .line 87
    .line 88
    .line 89
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    return-object p0

    .line 95
    :pswitch_1
    check-cast p1, Landroid/content/Context;

    .line 96
    .line 97
    iget-object v0, p0, Lnn/m;->i:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast v0, Lnn/t;

    .line 100
    .line 101
    const-string v1, "context"

    .line 102
    .line 103
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    new-instance v1, Landroid/webkit/WebView;

    .line 107
    .line 108
    invoke-direct {v1, p1}, Landroid/webkit/WebView;-><init>(Landroid/content/Context;)V

    .line 109
    .line 110
    .line 111
    iget-object p1, p0, Lnn/m;->g:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast p1, Lay0/k;

    .line 114
    .line 115
    iget-object v2, p0, Lnn/m;->h:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast v2, Landroid/widget/FrameLayout$LayoutParams;

    .line 118
    .line 119
    iget-object v3, p0, Lnn/m;->j:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast v3, Lnn/a;

    .line 122
    .line 123
    iget-object p0, p0, Lnn/m;->k:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast p0, Lnn/b;

    .line 126
    .line 127
    invoke-interface {p1, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    invoke-virtual {v1, v2}, Landroid/webkit/WebView;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 131
    .line 132
    .line 133
    iget-object p1, v0, Lnn/t;->g:Landroid/os/Bundle;

    .line 134
    .line 135
    if-eqz p1, :cond_0

    .line 136
    .line 137
    invoke-virtual {v1, p1}, Landroid/webkit/WebView;->restoreState(Landroid/os/Bundle;)Landroid/webkit/WebBackForwardList;

    .line 138
    .line 139
    .line 140
    :cond_0
    invoke-virtual {v1, v3}, Landroid/webkit/WebView;->setWebChromeClient(Landroid/webkit/WebChromeClient;)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v1, p0}, Landroid/webkit/WebView;->setWebViewClient(Landroid/webkit/WebViewClient;)V

    .line 144
    .line 145
    .line 146
    iget-object p0, v0, Lnn/t;->h:Ll2/j1;

    .line 147
    .line 148
    invoke-virtual {p0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 149
    .line 150
    .line 151
    return-object v1

    .line 152
    nop

    .line 153
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
