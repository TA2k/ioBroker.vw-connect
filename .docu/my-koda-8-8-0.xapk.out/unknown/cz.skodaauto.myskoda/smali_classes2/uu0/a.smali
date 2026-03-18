.class public final synthetic Luu0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lss0/k;


# direct methods
.method public synthetic constructor <init>(Lss0/k;I)V
    .locals 0

    .line 1
    iput p2, p0, Luu0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Luu0/a;->e:Lss0/k;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Luu0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ltu0/e;

    .line 7
    .line 8
    iget-object p0, p0, Luu0/a;->e:Lss0/k;

    .line 9
    .line 10
    iget-object p0, p0, Lss0/k;->f:Ljava/lang/String;

    .line 11
    .line 12
    invoke-direct {v0, p0}, Ltu0/e;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    return-object v0

    .line 16
    :pswitch_0
    new-instance v0, Ltu0/c;

    .line 17
    .line 18
    iget-object p0, p0, Luu0/a;->e:Lss0/k;

    .line 19
    .line 20
    iget-object p0, p0, Lss0/k;->j:Lss0/n;

    .line 21
    .line 22
    invoke-static {p0}, Llp/nd;->b(Ljava/lang/Enum;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-direct {v0, p0}, Ltu0/c;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    return-object v0

    .line 30
    :pswitch_1
    new-instance v0, Ltu0/g;

    .line 31
    .line 32
    iget-object p0, p0, Luu0/a;->e:Lss0/k;

    .line 33
    .line 34
    iget-object p0, p0, Lss0/k;->d:Lss0/m;

    .line 35
    .line 36
    invoke-static {p0}, Llp/nd;->b(Ljava/lang/Enum;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-direct {v0, p0}, Ltu0/g;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    return-object v0

    .line 44
    nop

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
