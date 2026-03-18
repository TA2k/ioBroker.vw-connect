.class public final Lw3/r1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw3/j2;


# instance fields
.field public a:Lay0/a;

.field public b:Ll2/j1;

.field public final c:Ll2/j1;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 5
    .line 6
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, Lw3/r1;->c:Ll2/j1;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a()J
    .locals 3

    .line 1
    iget-object v0, p0, Lw3/r1;->b:Ll2/j1;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lw3/r1;->a:Lay0/a;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Lt4/l;

    .line 14
    .line 15
    iget-wide v0, v0, Lt4/l;->a:J

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const-wide/16 v0, 0x0

    .line 19
    .line 20
    :goto_0
    new-instance v2, Lt4/l;

    .line 21
    .line 22
    invoke-direct {v2, v0, v1}, Lt4/l;-><init>(J)V

    .line 23
    .line 24
    .line 25
    invoke-static {v2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    iput-object v0, p0, Lw3/r1;->b:Ll2/j1;

    .line 30
    .line 31
    const/4 v0, 0x0

    .line 32
    iput-object v0, p0, Lw3/r1;->a:Lay0/a;

    .line 33
    .line 34
    :cond_1
    iget-object p0, p0, Lw3/r1;->b:Ll2/j1;

    .line 35
    .line 36
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    check-cast p0, Lt4/l;

    .line 44
    .line 45
    iget-wide v0, p0, Lt4/l;->a:J

    .line 46
    .line 47
    return-wide v0
.end method
