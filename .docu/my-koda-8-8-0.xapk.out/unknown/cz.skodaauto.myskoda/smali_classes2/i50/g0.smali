.class public final Li50/g0;
.super Landroid/webkit/WebViewClient;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Ljava/util/List;

.field public final synthetic b:Lpx0/i;


# direct methods
.method public constructor <init>(Ljava/util/List;Lpx0/i;)V
    .locals 0

    .line 1
    iput-object p1, p0, Li50/g0;->a:Ljava/util/List;

    .line 2
    .line 3
    iput-object p2, p0, Li50/g0;->b:Lpx0/i;

    .line 4
    .line 5
    invoke-direct {p0}, Landroid/webkit/WebViewClient;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onPageFinished(Landroid/webkit/WebView;Ljava/lang/String;)V
    .locals 6

    .line 1
    invoke-super {p0, p1, p2}, Landroid/webkit/WebViewClient;->onPageFinished(Landroid/webkit/WebView;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    iget-object p2, p0, Li50/g0;->a:Ljava/util/List;

    .line 5
    .line 6
    move-object v0, p2

    .line 7
    check-cast v0, Ljava/lang/Iterable;

    .line 8
    .line 9
    sget-object v4, Li50/f0;->d:Li50/f0;

    .line 10
    .line 11
    const/16 v5, 0x1f

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    const/4 v2, 0x0

    .line 15
    const/4 v3, 0x0

    .line 16
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    filled-new-array {p2}, [Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    const/4 v0, 0x1

    .line 25
    invoke-static {p2, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p2

    .line 29
    const-string v0, "load([%s])"

    .line 30
    .line 31
    invoke-static {v0, p2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p2

    .line 35
    if-eqz p1, :cond_0

    .line 36
    .line 37
    new-instance v0, Li50/e0;

    .line 38
    .line 39
    iget-object p0, p0, Li50/g0;->b:Lpx0/i;

    .line 40
    .line 41
    invoke-direct {v0, p0}, Li50/e0;-><init>(Lpx0/i;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p1, p2, v0}, Landroid/webkit/WebView;->evaluateJavascript(Ljava/lang/String;Landroid/webkit/ValueCallback;)V

    .line 45
    .line 46
    .line 47
    :cond_0
    return-void
.end method
