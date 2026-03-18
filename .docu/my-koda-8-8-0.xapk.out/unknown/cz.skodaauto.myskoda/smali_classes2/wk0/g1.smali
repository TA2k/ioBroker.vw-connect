.class public final synthetic Lwk0/g1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lwk0/s1;


# direct methods
.method public synthetic constructor <init>(Lwk0/s1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lwk0/g1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lwk0/g1;->e:Lwk0/s1;

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
    .locals 2

    .line 1
    iget v0, p0, Lwk0/g1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Llj0/b;

    .line 7
    .line 8
    iget-object p0, p0, Lwk0/g1;->e:Lwk0/s1;

    .line 9
    .line 10
    iget-object p0, p0, Lwk0/s1;->m:Lij0/a;

    .line 11
    .line 12
    const v1, 0x7f120635

    .line 13
    .line 14
    .line 15
    check-cast p0, Ljj0/f;

    .line 16
    .line 17
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    const-string v1, "Directions"

    .line 22
    .line 23
    invoke-direct {v0, p0, v1}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    return-object v0

    .line 27
    :pswitch_0
    new-instance v0, Llj0/a;

    .line 28
    .line 29
    iget-object p0, p0, Lwk0/g1;->e:Lwk0/s1;

    .line 30
    .line 31
    iget-object p0, p0, Lwk0/s1;->m:Lij0/a;

    .line 32
    .line 33
    const v1, 0x7f120682

    .line 34
    .line 35
    .line 36
    check-cast p0, Ljj0/f;

    .line 37
    .line 38
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    return-object v0

    .line 46
    nop

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
