.class public final Lhr/o0;
.super Lhr/k1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/ListIterator;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/util/AbstractList;


# direct methods
.method public synthetic constructor <init>(Ljava/util/AbstractList;Ljava/util/ListIterator;I)V
    .locals 0

    .line 1
    iput p3, p0, Lhr/o0;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lhr/o0;->g:Ljava/util/AbstractList;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    invoke-direct {p0, p2, p1}, Lhr/k1;-><init>(Ljava/util/Iterator;I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lhr/o0;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lhr/o0;->g:Ljava/util/AbstractList;

    .line 7
    .line 8
    check-cast p0, Lhr/q0;

    .line 9
    .line 10
    iget-object p0, p0, Lhr/q0;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lgr/e;

    .line 13
    .line 14
    invoke-interface {p0, p1}, Lgr/e;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_0
    iget-object p0, p0, Lhr/o0;->g:Ljava/util/AbstractList;

    .line 20
    .line 21
    check-cast p0, Lhr/p0;

    .line 22
    .line 23
    iget-object p0, p0, Lhr/p0;->f:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Lgr/e;

    .line 26
    .line 27
    invoke-interface {p0, p1}, Lgr/e;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final add(Ljava/lang/Object;)V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method

.method public final hasPrevious()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lhr/k1;->e:Ljava/util/Iterator;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ListIterator;

    .line 4
    .line 5
    invoke-interface {p0}, Ljava/util/ListIterator;->hasPrevious()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final nextIndex()I
    .locals 0

    .line 1
    iget-object p0, p0, Lhr/k1;->e:Ljava/util/Iterator;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ListIterator;

    .line 4
    .line 5
    invoke-interface {p0}, Ljava/util/ListIterator;->nextIndex()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final previous()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lhr/k1;->e:Ljava/util/Iterator;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ListIterator;

    .line 4
    .line 5
    invoke-interface {v0}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {p0, v0}, Lhr/k1;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public final previousIndex()I
    .locals 0

    .line 1
    iget-object p0, p0, Lhr/k1;->e:Ljava/util/Iterator;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ListIterator;

    .line 4
    .line 5
    invoke-interface {p0}, Ljava/util/ListIterator;->previousIndex()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final set(Ljava/lang/Object;)V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method
