.class public final Lcs0/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Las0/g;


# direct methods
.method public constructor <init>(Las0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcs0/v;->a:Las0/g;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lcs0/v;->a:Las0/g;

    .line 2
    .line 3
    iget-object p0, p0, Las0/g;->b:Lal0/i;

    .line 4
    .line 5
    new-instance v0, La50/h;

    .line 6
    .line 7
    const/16 v1, 0xe

    .line 8
    .line 9
    invoke-direct {v0, p0, v1}, La50/h;-><init>(Lyy0/i;I)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method
