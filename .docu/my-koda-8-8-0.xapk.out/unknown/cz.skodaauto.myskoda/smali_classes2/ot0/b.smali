.class public final synthetic Lot0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/n;

.field public final synthetic f:Lmt0/c;


# direct methods
.method public synthetic constructor <init>(Lay0/n;Lmt0/c;I)V
    .locals 0

    .line 1
    iput p3, p0, Lot0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lot0/b;->e:Lay0/n;

    .line 4
    .line 5
    iput-object p2, p0, Lot0/b;->f:Lmt0/c;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lot0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lot0/b;->f:Lmt0/c;

    .line 7
    .line 8
    invoke-virtual {v0}, Lmt0/c;->d()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sget-boolean v1, Llp/nb;->a:Z

    .line 13
    .line 14
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    iget-object p0, p0, Lot0/b;->e:Lay0/n;

    .line 19
    .line 20
    invoke-interface {p0, v0, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_0
    iget-object v0, p0, Lot0/b;->f:Lmt0/c;

    .line 27
    .line 28
    invoke-virtual {v0}, Lmt0/c;->d()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    sget-boolean v1, Llp/nb;->a:Z

    .line 33
    .line 34
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    iget-object p0, p0, Lot0/b;->e:Lay0/n;

    .line 39
    .line 40
    invoke-interface {p0, v0, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    nop

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
