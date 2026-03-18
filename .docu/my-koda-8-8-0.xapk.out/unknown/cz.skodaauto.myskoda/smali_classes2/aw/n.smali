.class public final Law/n;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:Lay0/k;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Landroid/widget/FrameLayout$LayoutParams;

.field public final synthetic i:Law/w;

.field public final synthetic j:Law/a;

.field public final synthetic k:Law/b;


# direct methods
.method public constructor <init>(Lay0/k;Lay0/k;Landroid/widget/FrameLayout$LayoutParams;Law/w;Law/a;Law/b;)V
    .locals 0

    .line 1
    iput-object p1, p0, Law/n;->f:Lay0/k;

    .line 2
    .line 3
    iput-object p2, p0, Law/n;->g:Lay0/k;

    .line 4
    .line 5
    iput-object p3, p0, Law/n;->h:Landroid/widget/FrameLayout$LayoutParams;

    .line 6
    .line 7
    iput-object p4, p0, Law/n;->i:Law/w;

    .line 8
    .line 9
    iput-object p5, p0, Law/n;->j:Law/a;

    .line 10
    .line 11
    iput-object p6, p0, Law/n;->k:Law/b;

    .line 12
    .line 13
    const/4 p1, 0x1

    .line 14
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Landroid/content/Context;

    .line 2
    .line 3
    const-string v0, "context"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Law/n;->f:Lay0/k;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-interface {v0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    check-cast v0, Landroid/webkit/WebView;

    .line 17
    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    :cond_0
    new-instance v0, Landroid/webkit/WebView;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Landroid/webkit/WebView;-><init>(Landroid/content/Context;)V

    .line 23
    .line 24
    .line 25
    :cond_1
    iget-object p1, p0, Law/n;->g:Lay0/k;

    .line 26
    .line 27
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Law/n;->h:Landroid/widget/FrameLayout$LayoutParams;

    .line 31
    .line 32
    invoke-virtual {v0, p1}, Landroid/webkit/WebView;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 33
    .line 34
    .line 35
    iget-object p1, p0, Law/n;->i:Law/w;

    .line 36
    .line 37
    iget-object v1, p1, Law/w;->g:Landroid/os/Bundle;

    .line 38
    .line 39
    if-eqz v1, :cond_2

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->restoreState(Landroid/os/Bundle;)Landroid/webkit/WebBackForwardList;

    .line 42
    .line 43
    .line 44
    :cond_2
    iget-object v1, p0, Law/n;->j:Law/a;

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->setWebChromeClient(Landroid/webkit/WebChromeClient;)V

    .line 47
    .line 48
    .line 49
    iget-object p0, p0, Law/n;->k:Law/b;

    .line 50
    .line 51
    invoke-virtual {v0, p0}, Landroid/webkit/WebView;->setWebViewClient(Landroid/webkit/WebViewClient;)V

    .line 52
    .line 53
    .line 54
    iget-object p0, p1, Law/w;->h:Ll2/j1;

    .line 55
    .line 56
    invoke-virtual {p0, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    return-object v0
.end method
