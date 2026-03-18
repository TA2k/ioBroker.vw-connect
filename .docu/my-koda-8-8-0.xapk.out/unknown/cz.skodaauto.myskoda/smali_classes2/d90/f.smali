.class public final synthetic Ld90/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:I

.field public final synthetic j:I


# direct methods
.method public synthetic constructor <init>(IIILay0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput p3, p0, Ld90/f;->d:I

    .line 2
    .line 3
    iput-object p5, p0, Ld90/f;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p6, p0, Ld90/f;->f:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p7, p0, Ld90/f;->g:Ljava/lang/String;

    .line 8
    .line 9
    iput-object p4, p0, Ld90/f;->h:Lay0/a;

    .line 10
    .line 11
    iput p1, p0, Ld90/f;->i:I

    .line 12
    .line 13
    iput p2, p0, Ld90/f;->j:I

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Ld90/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v5, p1

    .line 7
    check-cast v5, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget p1, p0, Ld90/f;->i:I

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v6

    .line 22
    iget-object v1, p0, Ld90/f;->e:Ljava/lang/String;

    .line 23
    .line 24
    iget-object v2, p0, Ld90/f;->f:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p0, Ld90/f;->g:Ljava/lang/String;

    .line 27
    .line 28
    iget-object v4, p0, Ld90/f;->h:Lay0/a;

    .line 29
    .line 30
    iget v7, p0, Ld90/f;->j:I

    .line 31
    .line 32
    invoke-static/range {v1 .. v7}, Lz70/l;->b0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/a;Ll2/o;II)V

    .line 33
    .line 34
    .line 35
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_0
    move-object v4, p1

    .line 39
    check-cast v4, Ll2/o;

    .line 40
    .line 41
    check-cast p2, Ljava/lang/Integer;

    .line 42
    .line 43
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    iget p1, p0, Ld90/f;->i:I

    .line 47
    .line 48
    or-int/lit8 p1, p1, 0x1

    .line 49
    .line 50
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 51
    .line 52
    .line 53
    move-result v5

    .line 54
    iget-object v0, p0, Ld90/f;->e:Ljava/lang/String;

    .line 55
    .line 56
    iget-object v1, p0, Ld90/f;->f:Ljava/lang/String;

    .line 57
    .line 58
    iget-object v2, p0, Ld90/f;->g:Ljava/lang/String;

    .line 59
    .line 60
    iget-object v3, p0, Ld90/f;->h:Lay0/a;

    .line 61
    .line 62
    iget v6, p0, Ld90/f;->j:I

    .line 63
    .line 64
    invoke-static/range {v0 .. v6}, Ljp/ag;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/a;Ll2/o;II)V

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    nop

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
