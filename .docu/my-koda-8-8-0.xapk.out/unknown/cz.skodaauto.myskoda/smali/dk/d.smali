.class public final synthetic Ldk/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:I

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IIIILay0/a;Lay0/a;I)V
    .locals 0

    .line 1
    const/4 p7, 0x1

    iput p7, p0, Ldk/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Ldk/d;->e:I

    iput p2, p0, Ldk/d;->f:I

    iput p3, p0, Ldk/d;->g:I

    iput p4, p0, Ldk/d;->h:I

    iput-object p5, p0, Ldk/d;->i:Lay0/a;

    iput-object p6, p0, Ldk/d;->j:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;IIILay0/a;I)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Ldk/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ldk/d;->j:Ljava/lang/Object;

    iput p2, p0, Ldk/d;->e:I

    iput p3, p0, Ldk/d;->f:I

    iput p4, p0, Ldk/d;->g:I

    iput-object p5, p0, Ldk/d;->i:Lay0/a;

    iput p6, p0, Ldk/d;->h:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Ldk/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ldk/d;->j:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v6, v0

    .line 9
    check-cast v6, Lay0/a;

    .line 10
    .line 11
    move-object v7, p1

    .line 12
    check-cast v7, Ll2/o;

    .line 13
    .line 14
    check-cast p2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/16 p1, 0x6001

    .line 20
    .line 21
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 22
    .line 23
    .line 24
    move-result v8

    .line 25
    iget v1, p0, Ldk/d;->e:I

    .line 26
    .line 27
    iget v2, p0, Ldk/d;->f:I

    .line 28
    .line 29
    iget v3, p0, Ldk/d;->g:I

    .line 30
    .line 31
    iget v4, p0, Ldk/d;->h:I

    .line 32
    .line 33
    iget-object v5, p0, Ldk/d;->i:Lay0/a;

    .line 34
    .line 35
    invoke-static/range {v1 .. v8}, Lel/b;->f(IIIILay0/a;Lay0/a;Ll2/o;I)V

    .line 36
    .line 37
    .line 38
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_0
    iget-object v0, p0, Ldk/d;->j:Ljava/lang/Object;

    .line 42
    .line 43
    move-object v1, v0

    .line 44
    check-cast v1, Ljava/lang/String;

    .line 45
    .line 46
    move-object v6, p1

    .line 47
    check-cast v6, Ll2/o;

    .line 48
    .line 49
    check-cast p2, Ljava/lang/Integer;

    .line 50
    .line 51
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    iget p1, p0, Ldk/d;->h:I

    .line 55
    .line 56
    or-int/lit8 p1, p1, 0x1

    .line 57
    .line 58
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 59
    .line 60
    .line 61
    move-result v7

    .line 62
    iget v2, p0, Ldk/d;->e:I

    .line 63
    .line 64
    iget v3, p0, Ldk/d;->f:I

    .line 65
    .line 66
    iget v4, p0, Ldk/d;->g:I

    .line 67
    .line 68
    iget-object v5, p0, Ldk/d;->i:Lay0/a;

    .line 69
    .line 70
    invoke-static/range {v1 .. v7}, Ldk/e;->a(Ljava/lang/String;IIILay0/a;Ll2/o;I)V

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
