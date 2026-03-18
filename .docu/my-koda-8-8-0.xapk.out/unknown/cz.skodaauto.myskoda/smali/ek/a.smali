.class public final synthetic Lek/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:I

.field public final synthetic g:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Lay0/k;ILl2/b1;I)V
    .locals 0

    .line 1
    iput p4, p0, Lek/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lek/a;->e:Lay0/k;

    .line 4
    .line 5
    iput p2, p0, Lek/a;->f:I

    .line 6
    .line 7
    iput-object p3, p0, Lek/a;->g:Ll2/b1;

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
    iget v0, p0, Lek/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lek/a;->g:Ll2/b1;

    .line 7
    .line 8
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 9
    .line 10
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    new-instance v0, Lic/a;

    .line 14
    .line 15
    iget v1, p0, Lek/a;->f:I

    .line 16
    .line 17
    invoke-direct {v0, v1}, Lic/a;-><init>(I)V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lek/a;->e:Lay0/k;

    .line 21
    .line 22
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    iget-object v0, p0, Lek/a;->g:Ll2/b1;

    .line 29
    .line 30
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 31
    .line 32
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    new-instance v0, Lac/q;

    .line 36
    .line 37
    iget v1, p0, Lek/a;->f:I

    .line 38
    .line 39
    invoke-direct {v0, v1}, Lac/q;-><init>(I)V

    .line 40
    .line 41
    .line 42
    iget-object p0, p0, Lek/a;->e:Lay0/k;

    .line 43
    .line 44
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
