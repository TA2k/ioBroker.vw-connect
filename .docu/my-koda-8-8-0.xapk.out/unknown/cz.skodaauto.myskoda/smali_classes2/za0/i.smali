.class public final synthetic Lza0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lza0/q;

.field public final synthetic e:Ly6/q;

.field public final synthetic f:Ly6/s;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:F

.field public final synthetic i:F

.field public final synthetic j:I

.field public final synthetic k:I


# direct methods
.method public synthetic constructor <init>(Lza0/q;Ly6/q;Ly6/s;Ljava/lang/String;FFII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lza0/i;->d:Lza0/q;

    .line 5
    .line 6
    iput-object p2, p0, Lza0/i;->e:Ly6/q;

    .line 7
    .line 8
    iput-object p3, p0, Lza0/i;->f:Ly6/s;

    .line 9
    .line 10
    iput-object p4, p0, Lza0/i;->g:Ljava/lang/String;

    .line 11
    .line 12
    iput p5, p0, Lza0/i;->h:F

    .line 13
    .line 14
    iput p6, p0, Lza0/i;->i:F

    .line 15
    .line 16
    iput p7, p0, Lza0/i;->j:I

    .line 17
    .line 18
    iput p8, p0, Lza0/i;->k:I

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    move-object v6, p1

    .line 2
    check-cast v6, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lza0/i;->j:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v7

    .line 17
    iget-object v0, p0, Lza0/i;->d:Lza0/q;

    .line 18
    .line 19
    iget-object v1, p0, Lza0/i;->e:Ly6/q;

    .line 20
    .line 21
    iget-object v2, p0, Lza0/i;->f:Ly6/s;

    .line 22
    .line 23
    iget-object v3, p0, Lza0/i;->g:Ljava/lang/String;

    .line 24
    .line 25
    iget v4, p0, Lza0/i;->h:F

    .line 26
    .line 27
    iget v5, p0, Lza0/i;->i:F

    .line 28
    .line 29
    iget v8, p0, Lza0/i;->k:I

    .line 30
    .line 31
    invoke-virtual/range {v0 .. v8}, Lza0/q;->k(Ly6/q;Ly6/s;Ljava/lang/String;FFLl2/o;II)V

    .line 32
    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0
.end method
