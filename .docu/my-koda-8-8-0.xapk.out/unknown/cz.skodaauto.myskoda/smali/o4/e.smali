.class public final Lo4/e;
.super Landroid/text/style/ClickableSpan;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lg4/n;


# direct methods
.method public constructor <init>(Lg4/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroid/text/style/ClickableSpan;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo4/e;->d:Lg4/n;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onClick(Landroid/view/View;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lo4/e;->d:Lg4/n;

    .line 2
    .line 3
    invoke-virtual {p0}, Lg4/n;->a()Lxf0/x1;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    iget-object p1, p0, Lxf0/x1;->a:Lay0/k;

    .line 10
    .line 11
    iget-object p0, p0, Lxf0/x1;->b:Lxf0/w1;

    .line 12
    .line 13
    iget-object p0, p0, Lxf0/w1;->b:Ljava/lang/String;

    .line 14
    .line 15
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method
