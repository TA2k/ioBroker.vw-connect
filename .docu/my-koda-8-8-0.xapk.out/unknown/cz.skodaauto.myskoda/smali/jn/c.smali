.class public final Ljn/c;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Ljn/a;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Ljn/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Ljn/c;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Ljn/c;->g:Lay0/k;

    .line 4
    .line 5
    iput-object p2, p0, Ljn/c;->h:Ljn/a;

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Ljn/c;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Number;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    iget-object v0, p0, Ljn/c;->h:Ljn/a;

    .line 13
    .line 14
    iget v1, v0, Ljn/a;->a:I

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    new-instance v0, Ljn/a;

    .line 20
    .line 21
    invoke-direct {v0, v1, p1}, Ljn/a;-><init>(II)V

    .line 22
    .line 23
    .line 24
    iget-object p0, p0, Ljn/c;->g:Lay0/k;

    .line 25
    .line 26
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    return-object p0

    .line 32
    :pswitch_0
    check-cast p1, Ljava/lang/Number;

    .line 33
    .line 34
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    iget-object v0, p0, Ljn/c;->h:Ljn/a;

    .line 39
    .line 40
    iget v1, v0, Ljn/a;->b:I

    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    new-instance v0, Ljn/a;

    .line 46
    .line 47
    invoke-direct {v0, p1, v1}, Ljn/a;-><init>(II)V

    .line 48
    .line 49
    .line 50
    iget-object p0, p0, Ljn/c;->g:Lay0/k;

    .line 51
    .line 52
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    return-object p0

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
