.class public final Lsp/c;
.super Lsp/d;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic g:I


# direct methods
.method public constructor <init>()V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Lsp/c;->g:I

    const/4 v1, 0x0

    .line 2
    invoke-direct {p0, v0, v1, v1}, Lsp/d;-><init>(ILsp/b;Ljava/lang/Float;)V

    return-void
.end method

.method public synthetic constructor <init>(ILsp/b;Ljava/lang/Float;I)V
    .locals 0

    .line 1
    iput p4, p0, Lsp/c;->g:I

    invoke-direct {p0, p1, p2, p3}, Lsp/d;-><init>(ILsp/b;Ljava/lang/Float;)V

    return-void
.end method


# virtual methods
.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget p0, p0, Lsp/c;->g:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "[SquareCap]"

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    const-string p0, "[RoundCap]"

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    const-string p0, "[ButtCap]"

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
