.class public final synthetic Ln70/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lay0/a;Lay0/a;II)V
    .locals 0

    .line 1
    iput p5, p0, Ln70/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ln70/d;->e:Lay0/a;

    .line 4
    .line 5
    iput-object p2, p0, Ln70/d;->f:Lay0/a;

    .line 6
    .line 7
    iput-object p3, p0, Ln70/d;->g:Lay0/a;

    .line 8
    .line 9
    iput p4, p0, Ln70/d;->h:I

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Ln70/d;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 11
    .line 12
    .line 13
    iget p2, p0, Ln70/d;->h:I

    .line 14
    .line 15
    or-int/lit8 p2, p2, 0x1

    .line 16
    .line 17
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    iget-object v0, p0, Ln70/d;->e:Lay0/a;

    .line 22
    .line 23
    iget-object v1, p0, Ln70/d;->f:Lay0/a;

    .line 24
    .line 25
    iget-object p0, p0, Ln70/d;->g:Lay0/a;

    .line 26
    .line 27
    invoke-static {v0, v1, p0, p1, p2}, Lz10/a;->o(Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 28
    .line 29
    .line 30
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 34
    .line 35
    .line 36
    iget p2, p0, Ln70/d;->h:I

    .line 37
    .line 38
    or-int/lit8 p2, p2, 0x1

    .line 39
    .line 40
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 41
    .line 42
    .line 43
    move-result p2

    .line 44
    iget-object v0, p0, Ln70/d;->e:Lay0/a;

    .line 45
    .line 46
    iget-object v1, p0, Ln70/d;->f:Lay0/a;

    .line 47
    .line 48
    iget-object p0, p0, Ln70/d;->g:Lay0/a;

    .line 49
    .line 50
    invoke-static {v0, v1, p0, p1, p2}, Lo50/a;->c(Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 55
    .line 56
    .line 57
    iget p2, p0, Ln70/d;->h:I

    .line 58
    .line 59
    or-int/lit8 p2, p2, 0x1

    .line 60
    .line 61
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 62
    .line 63
    .line 64
    move-result p2

    .line 65
    iget-object v0, p0, Ln70/d;->e:Lay0/a;

    .line 66
    .line 67
    iget-object v1, p0, Ln70/d;->f:Lay0/a;

    .line 68
    .line 69
    iget-object p0, p0, Ln70/d;->g:Lay0/a;

    .line 70
    .line 71
    invoke-static {v0, v1, p0, p1, p2}, Ln70/a;->p(Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 72
    .line 73
    .line 74
    goto :goto_0

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
