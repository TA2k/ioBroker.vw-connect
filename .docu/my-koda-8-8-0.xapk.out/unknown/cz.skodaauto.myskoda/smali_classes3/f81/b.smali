.class public final synthetic Lf81/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:[B

.field public final synthetic g:Lk71/d;


# direct methods
.method public synthetic constructor <init>(JLk71/d;[BI)V
    .locals 0

    .line 1
    iput p5, p0, Lf81/b;->d:I

    .line 2
    .line 3
    iput-wide p1, p0, Lf81/b;->e:J

    .line 4
    .line 5
    iput-object p3, p0, Lf81/b;->g:Lk71/d;

    .line 6
    .line 7
    iput-object p4, p0, Lf81/b;->f:[B

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lf81/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lf81/b;->g:Lk71/d;

    .line 7
    .line 8
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;

    .line 9
    .line 10
    iget-object v1, p0, Lf81/b;->f:[B

    .line 11
    .line 12
    iget-wide v2, p0, Lf81/b;->e:J

    .line 13
    .line 14
    invoke-static {v2, v3, v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->d(JLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;[B)Llx0/b0;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_0
    iget-object v0, p0, Lf81/b;->g:Lk71/d;

    .line 20
    .line 21
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;

    .line 22
    .line 23
    iget-object v1, p0, Lf81/b;->f:[B

    .line 24
    .line 25
    iget-wide v2, p0, Lf81/b;->e:J

    .line 26
    .line 27
    invoke-static {v2, v3, v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->o(JLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;[B)Llx0/b0;

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
