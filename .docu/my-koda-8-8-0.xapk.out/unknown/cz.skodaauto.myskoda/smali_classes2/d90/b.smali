.class public final synthetic Ld90/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/n;

.field public final synthetic f:Lb90/p;

.field public final synthetic g:Lb90/b;


# direct methods
.method public synthetic constructor <init>(Lay0/n;Lb90/p;Lb90/b;I)V
    .locals 0

    .line 1
    iput p4, p0, Ld90/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ld90/b;->e:Lay0/n;

    .line 4
    .line 5
    iput-object p2, p0, Ld90/b;->f:Lb90/p;

    .line 6
    .line 7
    iput-object p3, p0, Ld90/b;->g:Lb90/b;

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
    .locals 2

    .line 1
    iget v0, p0, Ld90/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ld90/b;->f:Lb90/p;

    .line 7
    .line 8
    iget-object v1, p0, Ld90/b;->g:Lb90/b;

    .line 9
    .line 10
    iget-object p0, p0, Ld90/b;->e:Lay0/n;

    .line 11
    .line 12
    invoke-interface {p0, v0, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_0
    iget-object v0, p0, Ld90/b;->f:Lb90/p;

    .line 19
    .line 20
    iget-object v1, p0, Ld90/b;->g:Lb90/b;

    .line 21
    .line 22
    iget-object p0, p0, Ld90/b;->e:Lay0/n;

    .line 23
    .line 24
    invoke-interface {p0, v0, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :pswitch_1
    iget-object v0, p0, Ld90/b;->f:Lb90/p;

    .line 29
    .line 30
    iget-object v1, p0, Ld90/b;->g:Lb90/b;

    .line 31
    .line 32
    iget-object p0, p0, Ld90/b;->e:Lay0/n;

    .line 33
    .line 34
    invoke-interface {p0, v0, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :pswitch_2
    iget-object v0, p0, Ld90/b;->f:Lb90/p;

    .line 39
    .line 40
    iget-object v1, p0, Ld90/b;->g:Lb90/b;

    .line 41
    .line 42
    iget-object p0, p0, Ld90/b;->e:Lay0/n;

    .line 43
    .line 44
    invoke-interface {p0, v0, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :pswitch_3
    iget-object v0, p0, Ld90/b;->f:Lb90/p;

    .line 49
    .line 50
    iget-object v1, p0, Ld90/b;->g:Lb90/b;

    .line 51
    .line 52
    iget-object p0, p0, Ld90/b;->e:Lay0/n;

    .line 53
    .line 54
    invoke-interface {p0, v0, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
