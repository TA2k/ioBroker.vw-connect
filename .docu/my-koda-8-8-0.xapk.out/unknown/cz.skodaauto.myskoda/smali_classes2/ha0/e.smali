.class public final synthetic Lha0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lga0/u;

.field public final synthetic e:I

.field public final synthetic f:I

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Z

.field public final synthetic i:I

.field public final synthetic j:I


# direct methods
.method public synthetic constructor <init>(Lga0/u;IILx2/s;ZII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lha0/e;->d:Lga0/u;

    .line 5
    .line 6
    iput p2, p0, Lha0/e;->e:I

    .line 7
    .line 8
    iput p3, p0, Lha0/e;->f:I

    .line 9
    .line 10
    iput-object p4, p0, Lha0/e;->g:Lx2/s;

    .line 11
    .line 12
    iput-boolean p5, p0, Lha0/e;->h:Z

    .line 13
    .line 14
    iput p6, p0, Lha0/e;->i:I

    .line 15
    .line 16
    iput p7, p0, Lha0/e;->j:I

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    move-object v5, p1

    .line 2
    check-cast v5, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lha0/e;->i:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v6

    .line 17
    iget-object v0, p0, Lha0/e;->d:Lga0/u;

    .line 18
    .line 19
    iget v1, p0, Lha0/e;->e:I

    .line 20
    .line 21
    iget v2, p0, Lha0/e;->f:I

    .line 22
    .line 23
    iget-object v3, p0, Lha0/e;->g:Lx2/s;

    .line 24
    .line 25
    iget-boolean v4, p0, Lha0/e;->h:Z

    .line 26
    .line 27
    iget v7, p0, Lha0/e;->j:I

    .line 28
    .line 29
    invoke-static/range {v0 .. v7}, Llp/r0;->e(Lga0/u;IILx2/s;ZLl2/o;II)V

    .line 30
    .line 31
    .line 32
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0
.end method
