.class public final Lvy0/u0;
.super Lvy0/w0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Lvy0/l;

.field public final synthetic g:Lvy0/y0;


# direct methods
.method public constructor <init>(Lvy0/y0;JLvy0/l;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lvy0/u0;->g:Lvy0/y0;

    .line 2
    .line 3
    invoke-direct {p0, p2, p3}, Lvy0/w0;-><init>(J)V

    .line 4
    .line 5
    .line 6
    iput-object p4, p0, Lvy0/u0;->f:Lvy0/l;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    .line 1
    iget-object v0, p0, Lvy0/u0;->g:Lvy0/y0;

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object p0, p0, Lvy0/u0;->f:Lvy0/l;

    .line 6
    .line 7
    invoke-virtual {p0, v0, v1}, Lvy0/l;->D(Lvy0/x;Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Lvy0/w0;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lvy0/u0;->f:Lvy0/l;

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
