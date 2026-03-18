.class public final synthetic Lkl0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:I

.field public final synthetic f:F

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Ljava/lang/String;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:I


# direct methods
.method public synthetic constructor <init>(ZIFLjava/lang/String;Ljava/lang/String;Lay0/a;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lkl0/c;->d:Z

    .line 5
    .line 6
    iput p2, p0, Lkl0/c;->e:I

    .line 7
    .line 8
    iput p3, p0, Lkl0/c;->f:F

    .line 9
    .line 10
    iput-object p4, p0, Lkl0/c;->g:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p5, p0, Lkl0/c;->h:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p6, p0, Lkl0/c;->i:Lay0/a;

    .line 15
    .line 16
    iput p7, p0, Lkl0/c;->j:I

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

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
    iget p1, p0, Lkl0/c;->j:I

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
    iget-boolean v0, p0, Lkl0/c;->d:Z

    .line 18
    .line 19
    iget v1, p0, Lkl0/c;->e:I

    .line 20
    .line 21
    iget v2, p0, Lkl0/c;->f:F

    .line 22
    .line 23
    iget-object v3, p0, Lkl0/c;->g:Ljava/lang/String;

    .line 24
    .line 25
    iget-object v4, p0, Lkl0/c;->h:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v5, p0, Lkl0/c;->i:Lay0/a;

    .line 28
    .line 29
    invoke-static/range {v0 .. v7}, Lkl0/d;->a(ZIFLjava/lang/String;Ljava/lang/String;Lay0/a;Ll2/o;I)V

    .line 30
    .line 31
    .line 32
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0
.end method
