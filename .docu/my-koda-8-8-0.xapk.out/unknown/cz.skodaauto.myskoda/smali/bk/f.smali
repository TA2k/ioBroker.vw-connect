.class public final synthetic Lbk/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lsd/g;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(Lsd/g;ILay0/k;I)V
    .locals 0

    .line 1
    const/4 p4, 0x2

    iput p4, p0, Lbk/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lbk/f;->e:Lsd/g;

    iput p2, p0, Lbk/f;->g:I

    iput-object p3, p0, Lbk/f;->f:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lsd/g;Lay0/k;II)V
    .locals 0

    .line 2
    iput p4, p0, Lbk/f;->d:I

    iput-object p1, p0, Lbk/f;->e:Lsd/g;

    iput-object p2, p0, Lbk/f;->f:Lay0/k;

    iput p3, p0, Lbk/f;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lbk/f;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    const/16 p2, 0x189

    .line 14
    .line 15
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    iget-object v0, p0, Lbk/f;->e:Lsd/g;

    .line 20
    .line 21
    iget v1, p0, Lbk/f;->g:I

    .line 22
    .line 23
    iget-object p0, p0, Lbk/f;->f:Lay0/k;

    .line 24
    .line 25
    invoke-static {v0, v1, p0, p1, p2}, Lbk/a;->s(Lsd/g;ILay0/k;Ll2/o;I)V

    .line 26
    .line 27
    .line 28
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_0
    iget p2, p0, Lbk/f;->g:I

    .line 32
    .line 33
    or-int/lit8 p2, p2, 0x1

    .line 34
    .line 35
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    iget-object v0, p0, Lbk/f;->e:Lsd/g;

    .line 40
    .line 41
    iget-object p0, p0, Lbk/f;->f:Lay0/k;

    .line 42
    .line 43
    invoke-static {v0, p0, p1, p2}, Lbk/a;->C(Lsd/g;Lay0/k;Ll2/o;I)V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :pswitch_1
    iget p2, p0, Lbk/f;->g:I

    .line 48
    .line 49
    or-int/lit8 p2, p2, 0x1

    .line 50
    .line 51
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 52
    .line 53
    .line 54
    move-result p2

    .line 55
    iget-object v0, p0, Lbk/f;->e:Lsd/g;

    .line 56
    .line 57
    iget-object p0, p0, Lbk/f;->f:Lay0/k;

    .line 58
    .line 59
    invoke-static {v0, p0, p1, p2}, Lbk/a;->r(Lsd/g;Lay0/k;Ll2/o;I)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
