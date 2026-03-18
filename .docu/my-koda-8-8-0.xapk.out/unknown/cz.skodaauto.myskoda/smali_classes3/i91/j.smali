.class public final Li91/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo3/a;


# instance fields
.field public final synthetic d:Li91/l1;

.field public final synthetic e:Lt4/c;

.field public final synthetic f:Le1/n1;

.field public final synthetic g:Ll2/b1;


# direct methods
.method public constructor <init>(Li91/l1;Lt4/c;Le1/n1;Ll2/b1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li91/j;->d:Li91/l1;

    .line 5
    .line 6
    iput-object p2, p0, Li91/j;->e:Lt4/c;

    .line 7
    .line 8
    iput-object p3, p0, Li91/j;->f:Le1/n1;

    .line 9
    .line 10
    iput-object p4, p0, Li91/j;->g:Ll2/b1;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final P(IJJ)J
    .locals 7

    .line 1
    iget-object v5, p0, Li91/j;->f:Le1/n1;

    .line 2
    .line 3
    iget-object v6, p0, Li91/j;->g:Ll2/b1;

    .line 4
    .line 5
    iget-object v3, p0, Li91/j;->d:Li91/l1;

    .line 6
    .line 7
    iget-object v4, p0, Li91/j;->e:Lt4/c;

    .line 8
    .line 9
    move v2, p1

    .line 10
    move-wide v0, p4

    .line 11
    invoke-static/range {v0 .. v6}, Li91/j0;->E0(JILi91/l1;Lt4/c;Le1/n1;Ll2/b1;)J

    .line 12
    .line 13
    .line 14
    move-result-wide p0

    .line 15
    return-wide p0
.end method

.method public final i(JJLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p1, p0, Li91/j;->g:Ll2/b1;

    .line 2
    .line 3
    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-interface {p1, p2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Li91/j;->d:Li91/l1;

    .line 9
    .line 10
    invoke-virtual {p0}, Li91/l1;->e()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Li91/l1;->c()Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-nez p0, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const-wide/16 p3, 0x0

    .line 21
    .line 22
    :goto_0
    new-instance p0, Lt4/q;

    .line 23
    .line 24
    invoke-direct {p0, p3, p4}, Lt4/q;-><init>(J)V

    .line 25
    .line 26
    .line 27
    return-object p0
.end method

.method public final y0(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p3, p0, Li91/j;->g:Ll2/b1;

    .line 2
    .line 3
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-interface {p3, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Li91/j;->d:Li91/l1;

    .line 9
    .line 10
    invoke-virtual {p0}, Li91/l1;->e()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Li91/l1;->c()Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-nez p0, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const-wide/16 p1, 0x0

    .line 21
    .line 22
    :goto_0
    new-instance p0, Lt4/q;

    .line 23
    .line 24
    invoke-direct {p0, p1, p2}, Lt4/q;-><init>(J)V

    .line 25
    .line 26
    .line 27
    return-object p0
.end method

.method public final z(IJ)J
    .locals 7

    .line 1
    iget-object v5, p0, Li91/j;->f:Le1/n1;

    .line 2
    .line 3
    iget-object v6, p0, Li91/j;->g:Ll2/b1;

    .line 4
    .line 5
    iget-object v3, p0, Li91/j;->d:Li91/l1;

    .line 6
    .line 7
    iget-object v4, p0, Li91/j;->e:Lt4/c;

    .line 8
    .line 9
    move v2, p1

    .line 10
    move-wide v0, p2

    .line 11
    invoke-static/range {v0 .. v6}, Li91/j0;->E0(JILi91/l1;Lt4/c;Le1/n1;Ll2/b1;)J

    .line 12
    .line 13
    .line 14
    move-result-wide p0

    .line 15
    return-wide p0
.end method
