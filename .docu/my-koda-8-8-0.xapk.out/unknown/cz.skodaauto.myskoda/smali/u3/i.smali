.class public final Lu3/i;
.super Llp/e1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lu3/h;

.field public final b:Ll2/j1;


# direct methods
.method public constructor <init>(Lu3/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu3/i;->a:Lu3/h;

    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    iput-object p1, p0, Lu3/i;->b:Ll2/j1;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a(Lu3/h;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lu3/i;->a:Lu3/h;

    .line 2
    .line 3
    if-ne p1, p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final b(Lu3/h;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lu3/i;->a:Lu3/h;

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    const-string p1, "Check failed."

    .line 7
    .line 8
    invoke-static {p1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    :goto_0
    iget-object p0, p0, Lu3/i;->b:Ll2/j1;

    .line 12
    .line 13
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    if-nez p0, :cond_1

    .line 18
    .line 19
    const/4 p0, 0x0

    .line 20
    :cond_1
    return-object p0
.end method
