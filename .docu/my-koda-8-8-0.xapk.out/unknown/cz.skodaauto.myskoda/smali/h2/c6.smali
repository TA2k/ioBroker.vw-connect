.class public final synthetic Lh2/c6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh2/r8;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lh2/r8;Lay0/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh2/c6;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/c6;->e:Lh2/r8;

    .line 4
    .line 5
    iput-object p2, p0, Lh2/c6;->f:Lay0/a;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lh2/c6;->d:I

    .line 2
    .line 3
    check-cast p1, Ljava/lang/Throwable;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object p1, p0, Lh2/c6;->e:Lh2/r8;

    .line 9
    .line 10
    invoke-virtual {p1}, Lh2/r8;->e()Z

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    if-nez p1, :cond_0

    .line 15
    .line 16
    iget-object p0, p0, Lh2/c6;->f:Lay0/a;

    .line 17
    .line 18
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_0
    iget-object p1, p0, Lh2/c6;->e:Lh2/r8;

    .line 25
    .line 26
    invoke-virtual {p1}, Lh2/r8;->e()Z

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    if-nez p1, :cond_1

    .line 31
    .line 32
    iget-object p0, p0, Lh2/c6;->f:Lay0/a;

    .line 33
    .line 34
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
