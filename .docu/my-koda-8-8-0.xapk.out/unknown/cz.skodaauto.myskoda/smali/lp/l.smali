.class public final Llp/l;
.super Ljp/m;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Serializable;


# instance fields
.field public final e:Ljava/lang/Object;

.field public final f:Lhr/l;


# direct methods
.method public constructor <init>(Ljava/lang/Object;Lhr/l;)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    invoke-direct {p0, v1, v0}, Ljp/m;-><init>(IZ)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Llp/l;->e:Ljava/lang/Object;

    .line 7
    .line 8
    iput-object p2, p0, Llp/l;->f:Lhr/l;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final getKey()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Llp/l;->e:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Llp/l;->f:Lhr/l;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setValue(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method
