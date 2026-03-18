.class public final synthetic Lot0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lnt0/e;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/n;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Z

.field public final synthetic l:I


# direct methods
.method public synthetic constructor <init>(Lnt0/e;Lay0/a;Lay0/a;Lay0/a;Lay0/n;Lay0/a;ZII)V
    .locals 0

    .line 1
    iput p9, p0, Lot0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lot0/c;->e:Lnt0/e;

    .line 4
    .line 5
    iput-object p2, p0, Lot0/c;->f:Lay0/a;

    .line 6
    .line 7
    iput-object p3, p0, Lot0/c;->g:Lay0/a;

    .line 8
    .line 9
    iput-object p4, p0, Lot0/c;->h:Lay0/a;

    .line 10
    .line 11
    iput-object p5, p0, Lot0/c;->i:Lay0/n;

    .line 12
    .line 13
    iput-object p6, p0, Lot0/c;->j:Lay0/a;

    .line 14
    .line 15
    iput-boolean p7, p0, Lot0/c;->k:Z

    .line 16
    .line 17
    iput p8, p0, Lot0/c;->l:I

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 20
    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lot0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v8, p1

    .line 7
    check-cast v8, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget p1, p0, Lot0/c;->l:I

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v9

    .line 22
    iget-object v1, p0, Lot0/c;->e:Lnt0/e;

    .line 23
    .line 24
    iget-object v2, p0, Lot0/c;->f:Lay0/a;

    .line 25
    .line 26
    iget-object v3, p0, Lot0/c;->g:Lay0/a;

    .line 27
    .line 28
    iget-object v4, p0, Lot0/c;->h:Lay0/a;

    .line 29
    .line 30
    iget-object v5, p0, Lot0/c;->i:Lay0/n;

    .line 31
    .line 32
    iget-object v6, p0, Lot0/c;->j:Lay0/a;

    .line 33
    .line 34
    iget-boolean v7, p0, Lot0/c;->k:Z

    .line 35
    .line 36
    invoke-static/range {v1 .. v9}, Lot0/a;->f(Lnt0/e;Lay0/a;Lay0/a;Lay0/a;Lay0/n;Lay0/a;ZLl2/o;I)V

    .line 37
    .line 38
    .line 39
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_0
    move-object v7, p1

    .line 43
    check-cast v7, Ll2/o;

    .line 44
    .line 45
    check-cast p2, Ljava/lang/Integer;

    .line 46
    .line 47
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    iget p1, p0, Lot0/c;->l:I

    .line 51
    .line 52
    or-int/lit8 p1, p1, 0x1

    .line 53
    .line 54
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 55
    .line 56
    .line 57
    move-result v8

    .line 58
    iget-object v0, p0, Lot0/c;->e:Lnt0/e;

    .line 59
    .line 60
    iget-object v1, p0, Lot0/c;->f:Lay0/a;

    .line 61
    .line 62
    iget-object v2, p0, Lot0/c;->g:Lay0/a;

    .line 63
    .line 64
    iget-object v3, p0, Lot0/c;->h:Lay0/a;

    .line 65
    .line 66
    iget-object v4, p0, Lot0/c;->i:Lay0/n;

    .line 67
    .line 68
    iget-object v5, p0, Lot0/c;->j:Lay0/a;

    .line 69
    .line 70
    iget-boolean v6, p0, Lot0/c;->k:Z

    .line 71
    .line 72
    invoke-static/range {v0 .. v8}, Lot0/a;->f(Lnt0/e;Lay0/a;Lay0/a;Lay0/a;Lay0/n;Lay0/a;ZLl2/o;I)V

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    nop

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
