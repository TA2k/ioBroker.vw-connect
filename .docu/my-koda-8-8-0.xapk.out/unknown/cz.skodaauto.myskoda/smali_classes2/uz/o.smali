.class public final synthetic Luz/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:I

.field public final synthetic j:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/String;ILjava/lang/String;Lay0/a;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Luz/o;->d:I

    .line 5
    .line 6
    iput-object p2, p0, Luz/o;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput p3, p0, Luz/o;->f:I

    .line 9
    .line 10
    iput-object p4, p0, Luz/o;->g:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p5, p0, Luz/o;->h:Lay0/a;

    .line 13
    .line 14
    iput p6, p0, Luz/o;->i:I

    .line 15
    .line 16
    iput p7, p0, Luz/o;->j:I

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
    iget p1, p0, Luz/o;->i:I

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
    iget v0, p0, Luz/o;->d:I

    .line 18
    .line 19
    iget-object v1, p0, Luz/o;->e:Ljava/lang/String;

    .line 20
    .line 21
    iget v2, p0, Luz/o;->f:I

    .line 22
    .line 23
    iget-object v3, p0, Luz/o;->g:Ljava/lang/String;

    .line 24
    .line 25
    iget-object v4, p0, Luz/o;->h:Lay0/a;

    .line 26
    .line 27
    iget v7, p0, Luz/o;->j:I

    .line 28
    .line 29
    invoke-static/range {v0 .. v7}, Luz/t;->q(ILjava/lang/String;ILjava/lang/String;Lay0/a;Ll2/o;II)V

    .line 30
    .line 31
    .line 32
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0
.end method
