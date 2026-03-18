.class public final Lkn/x;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lkn/f0;

.field public final synthetic h:Lkn/f0;

.field public final synthetic i:Lkn/c0;


# direct methods
.method public synthetic constructor <init>(Lkn/f0;Lkn/f0;Lkn/c0;I)V
    .locals 0

    .line 1
    iput p4, p0, Lkn/x;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lkn/x;->g:Lkn/f0;

    .line 4
    .line 5
    iput-object p2, p0, Lkn/x;->h:Lkn/f0;

    .line 6
    .line 7
    iput-object p3, p0, Lkn/x;->i:Lkn/c0;

    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lkn/x;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Throwable;

    .line 7
    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    iget-object p1, p0, Lkn/x;->g:Lkn/f0;

    .line 11
    .line 12
    iget-object v0, p0, Lkn/x;->h:Lkn/f0;

    .line 13
    .line 14
    if-ne p1, v0, :cond_0

    .line 15
    .line 16
    iget-object p0, p0, Lkn/x;->i:Lkn/c0;

    .line 17
    .line 18
    const/4 p1, 0x0

    .line 19
    iput p1, p0, Lkn/c0;->p:F

    .line 20
    .line 21
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_0
    check-cast p1, Ljava/lang/Throwable;

    .line 25
    .line 26
    if-nez p1, :cond_1

    .line 27
    .line 28
    iget-object p1, p0, Lkn/x;->g:Lkn/f0;

    .line 29
    .line 30
    iget-object v0, p0, Lkn/x;->h:Lkn/f0;

    .line 31
    .line 32
    if-ne p1, v0, :cond_1

    .line 33
    .line 34
    iget-object p0, p0, Lkn/x;->i:Lkn/c0;

    .line 35
    .line 36
    const/4 p1, 0x0

    .line 37
    iput p1, p0, Lkn/c0;->p:F

    .line 38
    .line 39
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_1
    check-cast p1, Ljava/lang/Throwable;

    .line 43
    .line 44
    if-nez p1, :cond_2

    .line 45
    .line 46
    iget-object p1, p0, Lkn/x;->g:Lkn/f0;

    .line 47
    .line 48
    iget-object v0, p0, Lkn/x;->h:Lkn/f0;

    .line 49
    .line 50
    if-ne p1, v0, :cond_2

    .line 51
    .line 52
    iget-object p0, p0, Lkn/x;->i:Lkn/c0;

    .line 53
    .line 54
    iget-object p1, p0, Lkn/c0;->b:Ll2/j1;

    .line 55
    .line 56
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 57
    .line 58
    invoke-virtual {p1, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    const/4 p1, 0x0

    .line 62
    iput p1, p0, Lkn/c0;->p:F

    .line 63
    .line 64
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    return-object p0

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
