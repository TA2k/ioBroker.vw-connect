.class public final Lt1/f1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg1/q2;


# instance fields
.field public final synthetic a:Lg1/q2;

.field public final b:Ll2/h0;

.field public final c:Ll2/h0;


# direct methods
.method public constructor <init>(Lg1/q2;Lt1/h1;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt1/f1;->a:Lg1/q2;

    .line 5
    .line 6
    new-instance p1, Lt1/e1;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-direct {p1, p2, v0}, Lt1/e1;-><init>(Lt1/h1;I)V

    .line 10
    .line 11
    .line 12
    invoke-static {p1}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, p0, Lt1/f1;->b:Ll2/h0;

    .line 17
    .line 18
    new-instance p1, Lt1/e1;

    .line 19
    .line 20
    const/4 v0, 0x1

    .line 21
    invoke-direct {p1, p2, v0}, Lt1/e1;-><init>(Lt1/h1;I)V

    .line 22
    .line 23
    .line 24
    invoke-static {p1}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    iput-object p1, p0, Lt1/f1;->c:Ll2/h0;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lt1/f1;->a:Lg1/q2;

    .line 2
    .line 3
    invoke-interface {p0}, Lg1/q2;->a()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final b()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lt1/f1;->c:Ll2/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lt1/f1;->a:Lg1/q2;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2, p3}, Lg1/q2;->c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final d()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lt1/f1;->b:Ll2/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final e(F)F
    .locals 0

    .line 1
    iget-object p0, p0, Lt1/f1;->a:Lg1/q2;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lg1/q2;->e(F)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
