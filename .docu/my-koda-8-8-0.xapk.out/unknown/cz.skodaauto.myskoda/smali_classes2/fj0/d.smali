.class public final Lfj0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lfj0/l;


# direct methods
.method public constructor <init>(Lfj0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lfj0/d;->a:Lfj0/l;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lfj0/d;->a:Lfj0/l;

    .line 2
    .line 3
    check-cast p0, Ldj0/c;

    .line 4
    .line 5
    iget-object p0, p0, Ldj0/c;->b:Lyy0/c2;

    .line 6
    .line 7
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Ljava/lang/String;

    .line 12
    .line 13
    return-object p0
.end method
